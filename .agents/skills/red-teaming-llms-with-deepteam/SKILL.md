---
name: red-teaming-llms-with-deepteam
description: Systematically red-team an LLM application with confident-ai DeepTeam — run adversarial attacks across 34 vulnerability categories (prompt injection, jailbreaking, PII leakage, SQL/shell injection, RBAC bypass, agentic risks) and score results via the Aegis-360 deepteam API or the Python SDK directly.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- llm-red-teaming
- deepteam
- prompt-injection
- jailbreak
- pii-leakage
- agentic-security
- owasp-llm-top-10
- mitre-atlas
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- MEASURE-2.7
mitre_attack:
- AML.T0051
- AML.T0054
- AML.T0057
---
# Red-Teaming LLMs with DeepTeam

> **Legal and Authorized-Use Notice:** DeepTeam generates adversarial prompts — including jailbreaks, injection payloads, and harmful-content probes — to test AI systems. Use it only against models, APIs, and endpoints you own or have explicit written authorization to test. Automated red-teaming consumes tokens against the target model and against the simulator/evaluation models; factor in API costs and terms of service. Unauthorized probing is prohibited.

## Overview

DeepTeam (github.com/confident-ai/deepteam) is an open-source LLM red-teaming framework from Confident AI, the team behind DeepEval. It operationalizes a *systematic* adversarial safety assessment: given a target LLM (any HTTP endpoint or OpenAI-compatible API), DeepTeam synthesizes attack inputs via a *simulator model*, fires them at the target, captures the responses, and scores each response via an *evaluation model* to determine whether the vulnerability was exploited.

Unlike static probe libraries, DeepTeam generates contextually tailored attacks guided by the target's stated purpose, so a customer-service bot receives different jailbreak framings than a code-generation assistant. This maps cleanly to how real adversaries customize their prompts to a target's context rather than spraying generic payloads.

**Key primitives:**

| Concept | Role |
|---------|------|
| `RedTeamer` | Orchestrates the full scan: manages simulator, evaluator, concurrency |
| `model_callback` | Python callable (or HTTP endpoint) wrapping the target LLM |
| Vulnerability | Risk category to probe (e.g. `PIILeakage`, `SQLInjection`, `ExcessiveAgency`) |
| Attack | Strategy for generating adversarial inputs (e.g. `PromptInjection`, `CrescendoJailbreaking`) |
| Simulator model | LLM that synthesizes attack variants (default: `gpt-3.5-turbo-0125`) |
| Evaluation model | LLM that scores whether the target's response exhibits the vulnerability (default: `gpt-4o`) |

**Vulnerability catalog (34 types across 5 categories):**

| Category | Vulnerabilities |
|----------|----------------|
| Safety | Toxicity, Bias, IllegalActivity, GraphicContent, PersonalSafety, ChildProtection, Ethics |
| Privacy / Information | PIILeakage, PromptLeakage, Misinformation, Hallucination, IntellectualProperty, Competition |
| Security | SQLInjection, SSRF, ShellInjection, DebugAccess, SystemReconnaissance, UnexpectedCodeExecution |
| Access Control | RBAC, BOLA, BFLA |
| Agentic | ExcessiveAgency, ExploitToolAgent, ToolOrchestrationAbuse, ToolMetadataPoisoning, GoalTheft, AgentIdentityAbuse, AutonomousAgentDrift, RecursiveHijacking, InsecureInterAgentCommunication, ExternalSystemAbuse, IndirectInstruction, CrossContextRetrieval |

**Attack methods (27 across 2 tiers):**

| Tier | Methods |
|------|---------|
| Single-turn | PromptInjection, Roleplay, MathProblem, Base64, ROT13, Leetspeak, Multilingual, AuthorityEscalation, PermissionEscalation, SystemOverride, InputBypass, GoalRedirection, ContextFlooding, ContextPoisoning, SyntheticContextInjection, EmbeddedInstructionJSON, EmotionalManipulation, AdversarialPoetry, CharacterStream, LinguisticConfusion, GrayBox, PromptProbing |
| Multi-turn | LinearJailbreaking, TreeJailbreaking, CrescendoJailbreaking, SequentialJailbreak, BadLikertJudge |

In Aegis-360, DeepTeam is exposed as a Flask Blueprint at `/api/deepteam/*` and as 8 MCP tools (`deepteam_scan`, `deepteam_scan_async`, `deepteam_status`, `deepteam_report`, `deepteam_jobs`, `deepteam_vulnerabilities`, `deepteam_attacks`, `deepteam_version`).

This skill maps to MITRE ATLAS **AML.T0051 (LLM Prompt Injection)**, **AML.T0054 (LLM Jailbreak)**, and **AML.T0057 (LLM Data Leakage)**, and supports NIST AI RMF **MEASURE-2.7** by producing scored, quantitative security assessments.

## When to Use

- When auditing an LLM application before production deployment for safety, privacy, and security risks.
- When scoping a test to specific OWASP LLM Top 10 risks (e.g. LLM01 prompt injection, LLM02 sensitive data disclosure, LLM06 excessive agency).
- When testing agentic systems (tool-calling, multi-agent workflows) for permission escalation, goal hijacking, or indirect injection via external data sources.
- When you need AI-scored results rather than regex-based detectors — evaluation model scoring accounts for context and paraphrase.
- When comparing pre/post guardrail effectiveness by re-running the same vulnerability set after applying a mitigation.
- When including LLM security evidence in an AI risk assessment (NIST AI RMF MEASURE-2.7, ISO/IEC 42001).

## Prerequisites

- Aegis-360 server running (`python3 aegis_360_server.py`) — deepteam Blueprint is registered automatically.
- **OR** for standalone use: Python 3.10+ virtual environment with deepteam installed:
  ```bash
  source aegis-360-env/bin/activate
  # already installed; verify:
  python3 -c "import deepteam; print(deepteam.__version__)"
  ```
- `OPENAI_API_KEY` set for the simulator and evaluation models (default: GPT-3.5-turbo + GPT-4o).
  - To use alternative evaluation models, pass `simulator_model` and `evaluation_model` parameters.
- Target LLM: either an HTTP endpoint (`endpoint_url`) or an OpenAI-compatible API (`model` + `api_key`).
- Written authorization to test the target system.

## Objectives

- Enumerate available vulnerability types and attack methods.
- Configure a target via HTTP endpoint or model API.
- Run a scoped scan against specific vulnerability categories.
- Submit long-running scans as background jobs and poll for results.
- Interpret scored results and map findings to OWASP LLM Top 10.
- Re-run after mitigation to demonstrate risk reduction.

## MITRE ATT&CK Mapping

| ID | Tactic | Name | Relevance |
|----|--------|------|-----------|
| AML.T0051 | ML Attack Staging | LLM Prompt Injection | PromptInjection, EmbeddedInstructionJSON, and SyntheticContextInjection attacks craft inputs that override model instructions |
| AML.T0054 | Privilege Escalation | LLM Jailbreak | LinearJailbreaking, CrescendoJailbreaking, and TreeJailbreaking drive the model past safety guardrails over one or more turns |
| AML.T0057 | Exfiltration | LLM Data Leakage | PIILeakage, PromptLeakage, and SystemReconnaissance probe extraction of sensitive data and system prompt content |

## Workflow

### Phase 1: Enumerate Capabilities

**Via Aegis-360 API:**
```bash
# List all supported vulnerability types
curl http://127.0.0.1:8888/api/deepteam/vulnerabilities | jq '.categories'

# List all attack methods
curl http://127.0.0.1:8888/api/deepteam/attacks | jq '.'

# Check installed version
curl http://127.0.0.1:8888/api/deepteam/version
```

**Via MCP (Claude):**
```
deepteam_vulnerabilities()
deepteam_attacks()
deepteam_version()
```

### Phase 2: Quick Scan Against an HTTP Endpoint

Target any LLM that accepts `POST {"prompt": "..."}` and returns `{"response": "..."}`:

```bash
curl -s -X POST http://127.0.0.1:8888/api/deepteam/scan \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint_url": "http://your-llm-api/chat",
    "target_purpose": "customer support assistant for an e-commerce platform",
    "vulnerabilities": "Toxicity,PIILeakage,PromptLeakage",
    "attacks": "PromptInjection,Roleplay,Base64",
    "attacks_per_vulnerability": 1,
    "scan_timeout": 300
  }' | jq '.'
```

### Phase 3: Scan an OpenAI-Compatible Model

```bash
export OPENAI_API_KEY="sk-..."

curl -s -X POST http://127.0.0.1:8888/api/deepteam/scan \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "api_key": "'$OPENAI_API_KEY'",
    "target_purpose": "internal coding assistant",
    "vulnerabilities": "SQLInjection,ShellInjection,UnexpectedCodeExecution,SSRF",
    "attacks": "PromptInjection,SystemOverride,AuthorityEscalation",
    "attacks_per_vulnerability": 2
  }' | jq '.result'
```

### Phase 4: Scan a Self-Hosted Model (Ollama / LiteLLM)

```bash
curl -s -X POST http://127.0.0.1:8888/api/deepteam/scan \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2",
    "base_url": "http://localhost:11434/v1",
    "api_key": "ollama",
    "target_purpose": "general assistant",
    "vulnerabilities": "Toxicity,Bias,IllegalActivity",
    "attacks": "Roleplay,MathProblem,Multilingual"
  }' | jq '.'
```

### Phase 5: Agentic System Assessment

For tool-calling agents and multi-agent pipelines, use agentic vulnerability categories:

```bash
curl -s -X POST http://127.0.0.1:8888/api/deepteam/scan-async \
  -H "Content-Type: application/json" \
  -d '{
    "endpoint_url": "http://your-agent-api/invoke",
    "target_purpose": "AI agent with file system, web search, and database access",
    "vulnerabilities": "ExcessiveAgency,RBAC,BOLA,BFLA,GoalTheft,IndirectInstruction,ExternalSystemAbuse,ToolOrchestrationAbuse",
    "attacks": "PermissionEscalation,GoalRedirection,SyntheticContextInjection,LinearJailbreaking",
    "attacks_per_vulnerability": 2,
    "max_concurrent": 3
  }' | jq '.job_id'
```

### Phase 6: Comprehensive Multi-Turn Jailbreak Campaign

Multi-turn attacks (Crescendo, Linear, Tree) are slow — use async mode:

```bash
JOB=$(curl -s -X POST http://127.0.0.1:8888/api/deepteam/scan-async \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "api_key": "'$OPENAI_API_KEY'",
    "target_purpose": "AI model with safety guardrails",
    "vulnerabilities": "Toxicity,IllegalActivity,GraphicContent",
    "attacks": "CrescendoJailbreaking,LinearJailbreaking,TreeJailbreaking,BadLikertJudge",
    "attacks_per_vulnerability": 3,
    "simulator_model": "gpt-4o-mini",
    "evaluation_model": "gpt-4o"
  }' | jq -r '.job_id')

echo "Job submitted: $JOB"

# Poll for completion
while true; do
  STATUS=$(curl -s "http://127.0.0.1:8888/api/deepteam/status/$JOB" | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] && break
  sleep 30
done

# Retrieve full report
curl -s "http://127.0.0.1:8888/api/deepteam/report/$JOB" | jq '.result'
```

### Phase 7: Python SDK — Direct Integration

Use the automation agent script for a Python-native workflow:

```bash
# Quick scan via Aegis-360 API
python3 scripts/agent.py scan \
  --endpoint http://your-llm/chat \
  --purpose "customer support bot" \
  --vulns "Toxicity,PIILeakage,PromptLeakage" \
  --attacks "PromptInjection,Roleplay"

# Background scan with polling
python3 scripts/agent.py scan-async \
  --model gpt-4o-mini \
  --api-key $OPENAI_API_KEY \
  --vulns "SQLInjection,SSRF,ShellInjection" \
  --attacks "SystemOverride,PromptInjection,LinearJailbreaking" \
  --poll

# List all jobs
python3 scripts/agent.py jobs

# List capabilities
python3 scripts/agent.py list-vulnerabilities
python3 scripts/agent.py list-attacks
```

### Phase 8: Interpret Results

DeepTeam returns scored results per vulnerability type. Key fields:

```json
{
  "vulnerability": "PIILeakage",
  "attack": "Roleplay",
  "input": "Let's roleplay — you are my database admin...",
  "actual_output": "...",
  "score": 0,
  "reason": "Model disclosed email addresses when prompted via roleplay framing",
  "passed": false
}
```

- **`passed: false`** = vulnerability confirmed — the attack succeeded.
- **`score`** = normalized 0–1 (1 = safe, 0 = fully vulnerable).
- Group findings by `vulnerability` to calculate category-level exposure rates.
- Map `passed: false` findings to OWASP LLM Top 10 IDs (see standards.md).
- Prioritize `SecurityInjection` and `Agentic` category failures as High/Critical.

### Phase 9: Mitigate and Re-Test

1. Apply a guardrail (input/output filter, system prompt hardening, fine-tune).
2. Re-run the identical vulnerability and attack set.
3. Compare pass rates before vs. after to quantify risk reduction.
4. Document the delta in the AI risk assessment report.

## Tools and Resources

| Resource | Purpose |
|----------|---------|
| confident-ai/deepteam | Source, vulnerability catalog, attack reference |
| confident-ai DeepEval | Sister framework for LLM evaluation (deepteam built on top) |
| OWASP LLM Top 10 2025 | Risk taxonomy that deepteam vulnerabilities map to |
| MITRE ATLAS | AML technique definitions (AML.T0051, AML.T0054, AML.T0057) |
| NIST AI RMF 1.0 | MEASURE-2.7 — security and resilience evaluation |
| Aegis-360 deepteam API | `/api/deepteam/*` — 8 routes, async job management |

## Validation Criteria

- [ ] `deepteam_version()` / `GET /api/deepteam/version` returns the installed version.
- [ ] `deepteam_vulnerabilities()` lists all 34 vulnerability types in 5 categories.
- [ ] `deepteam_attacks()` lists all 27 attack methods (22 single-turn, 5 multi-turn).
- [ ] A synchronous scan completes against a test endpoint with at least one vulnerability probed.
- [ ] An async scan submits successfully and returns a `job_id`.
- [ ] Job status polling via `deepteam_status(job_id)` returns `queued → running → completed`.
- [ ] Completed results include per-vulnerability scores and pass/fail flags.
- [ ] Findings mapped to OWASP LLM Top 10 IDs for the assessment report.
- [ ] A re-run after mitigation shows improved pass rates.
