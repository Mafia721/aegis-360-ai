# SurfaceZero v2.1
## Pre-Authentication Attack Surface Enumeration + AI Analyst
**By BinaryGalaxys Security | For Authorized Penetration Testing Only**

---

## Requirements

| Item | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 / Debian 11 / Kali 2022+ | Kali Linux 2024+ |
| Python | 3.10 | 3.11 / 3.12 |
| RAM | 512 MB | 2 GB+ |
| AI API Key | Optional | ANTHROPIC_API_KEY or DEEPSEEK_API_KEY |

---

## Installation

### Method 1: Automated (Recommended)
```bash
unzip surfacezero_v2.1.zip
cd surfacezero_v2.1
chmod +x install.sh
./install.sh
```

### Method 2: Manual
```bash
unzip surfacezero_v2.1.zip
cd surfacezero_v2.1
pip3 install -r requirements.txt --break-system-packages
python3 preloginscan.py --help
```

### Method 3: Virtual Environment
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 preloginscan.py --help
```

### Method 4: pip editable install
```bash
pip3 install -e . --break-system-packages
surfacezero --help
```

### Setting AI API Keys
```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude
export DEEPSEEK_API_KEY="sk-..."        # DeepSeek
export OPENAI_API_KEY="sk-..."          # GPT-4o
export GEMINI_API_KEY="AIza..."         # Gemini

# Persist across sessions
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.bashrc && source ~/.bashrc
```

---

## Quick Start

```bash
# Full scan
surfacezero scan -t https://app.example.com

# Scan + AI analysis
surfacezero scan -t https://app.example.com --ai-analyze --ai-model claude --engagement-id PT37818

# Through Burp Suite
surfacezero scan -t https://app.example.com --proxy http://127.0.0.1:8080 --skip-ssl

# AI analysis on existing scan
surfacezero analyze -i output/scan_*.json --model deepseek

# Interactive AI chat
surfacezero chat -i output/scan_*.json --model claude
```

---

## Commands

### `scan` — Full pipeline
```
-t  --target TEXT          Target URL (required)
-o  --output TEXT          Output directory [output]
    --threads INT          Concurrent threads [10]
    --timeout INT          Timeout seconds [15]
    --proxy TEXT           Proxy (e.g. http://127.0.0.1:8080)
    --skip-ssl             Disable SSL verification
    --cookie TEXT          Cookie header value
-m  --modules TEXT         Modules: all | secrets,js,graphql,cors,
                           headers,paths,pii,api,api_harvest,tokens
    --aggressive           Auth bypass + HTTP method testing
    --engagement-id TEXT   Tag for report (e.g. PT37818)
    --ai-analyze           Chain AI analysis after scan
    --ai-model TEXT        Model for AI [claude]
    --ai-features TEXT     AI features [threat-model,kill-chain,mitre]
    --api-key TEXT         AI API key
-v  --verbose              Verbose output
```

### `analyze` — AI threat analysis
```
-i  --input TEXT           Scan JSON path (required)
-m  --model TEXT           claude | deepseek | gpt4 | gemini | ollama:llama3
-f  --features TEXT        threat-model,kill-chain,mitre,exploits,remediation
-o  --output TEXT          HTML report output path
    --api-key TEXT         AI API key
    --ollama-host TEXT     Ollama URL [http://localhost:11434]
```

### `chat` — Interactive AI session
```
-i  --input TEXT           Scan JSON path (required)
-m  --model TEXT           AI model
    --api-key TEXT         AI API key

In-session: 'summary' | 'clear' | 'exit'
```

### `report` — Generate report
```
surfacezero report -i output/scan.json -f html -o report.html
surfacezero report -i output/scan.json -f md   -o report.md
```

---

## Scan Modules

| Module | Flag | What It Finds |
|---|---|---|
| JS Analyzer | `js` | JS files, endpoints, frameworks, source maps, cloud URLs |
| Secrets | `secrets` | 45 patterns: AWS/GCP/Azure keys, JWTs, DB URIs, tokens |
| GraphQL | `graphql` | Introspection, mutations, batch queries, field suggestions |
| CORS + Headers | `cors,headers` | Origin reflection, missing headers, CSP weaknesses |
| Cookies + Tokens | `cookies,tokens` | HttpOnly/Secure/SameSite, JWT leaks, weak alg |
| PII | `pii` | Email, SSN, credit card, Aadhaar, PAN, phone, address |
| Paths | `paths` | 123 paths: .env, swagger, actuator, admin, git, backups |
| API Harvester | `api_harvest` | 114 probes, live JSON retrieval, auth bypass testing |

---

## AI Features

| Feature | Output |
|---|---|
| `threat-model` | STRIDE analysis across all 6 categories + top risks |
| `kill-chain` | Unified Kill Chain phases with MITRE IDs + choke points |
| `mitre` | ATT&CK mapping with tactic heatmap + detection notes |
| `exploits` | Per-finding PoC approach, CVSS estimate, chaining |
| `remediation` | Prioritized roadmap: immediate/short/long-term |

## AI Models

| Alias | Provider | API Env Var | Cost |
|---|---|---|---|
| `claude` / `claude-haiku` / `claude-opus` | Anthropic | `ANTHROPIC_API_KEY` | Paid |
| `deepseek` / `deepseek-chat` | DeepSeek | `DEEPSEEK_API_KEY` | Very cheap |
| `gpt4` / `gpt-4o-mini` | OpenAI | `OPENAI_API_KEY` | Paid |
| `gemini` / `gemini-pro` | Google | `GEMINI_API_KEY` | Free tier |
| `ollama:llama3` / `ollama:mistral` / `ollama:deepseek-r1:7b` | Local | None | Free |

---

## API Data Harvester

Actively retrieves live data from unauthenticated endpoints.

**114 probes across:** users, config, settings, admin, search, export, actuator, JWKS, OAuth userinfo, tenant/org APIs.

**Auth bypass headers tested (--aggressive):**
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
Authorization: Bearer null
Authorization: Bearer undefined
X-Api-Key: null
X-Auth-Token: guest
```

**Sensitivity patterns (19):** user records, password hashes, API keys, JWTs, emails, credit cards, SSNs, Aadhaar/PAN, AWS keys, private keys, DB URIs, admin flags, S3 URLs, stack traces.

---

## Output Files

```
output/
├── preloginscan_<target>_<ts>.json        # Full raw scan
├── api_harvest_<target>_<ts>.json         # Retrieved API data (JSON)
├── ai_report_<target>_<ts>.html           # Combined HTML report
└── ai_report_<target>_<ts>_ai_raw.json   # Raw AI analysis
```

---

## Burp Suite Integration

```bash
surfacezero scan -t https://target.com --proxy http://127.0.0.1:8080 --skip-ssl
```
All requests appear in Burp Proxy history for manual review.

---

## Ollama (Offline / Air-Gapped)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3          # 4.7GB
ollama pull deepseek-r1:7b  # 4.7GB - best reasoning

surfacezero analyze -i output/scan.json --model ollama:deepseek-r1:7b
surfacezero chat -i output/scan.json --model ollama:llama3
```

---

## Common Pentest Scenarios

```bash
# Cobalt / Infor OS Portal
surfacezero scan \
  -t https://portal-qa.infor.com \
  --proxy http://127.0.0.1:8080 --skip-ssl \
  --engagement-id PT37818 --aggressive \
  --ai-analyze --ai-model claude \
  --ai-features threat-model,kill-chain,mitre,exploits -v

# SaaS recon
surfacezero scan -t https://app.target.com
surfacezero analyze -i output/scan_*.json --model deepseek \
  --features threat-model,kill-chain,exploits,remediation

# Secret + GraphQL hunt only
surfacezero scan -t https://target.com -m secrets,js,graphql

# API data harvest only
surfacezero scan -t https://target.com -m api_harvest,paths --aggressive

# Air-gapped
surfacezero scan -t https://internal.corp --skip-ssl
surfacezero analyze -i output/scan_*.json --model ollama:deepseek-r1:7b
```

---

## Troubleshooting

```bash
# Missing module
pip3 install httpx rich beautifulsoup4 lxml --break-system-packages

# SSL errors
surfacezero scan -t https://target.com --skip-ssl

# Burp proxy not working
# → Ensure Burp listener on 127.0.0.1:8080, disable intercept

# Ollama not connecting
ollama serve &
surfacezero analyze -i scan.json --model ollama:llama3 --ollama-host http://127.0.0.1:11434
```

---

## Legal Disclaimer

For **authorized penetration testing only**. Unauthorized use is illegal under CFAA, UK Computer Misuse Act, India IT Act 2000, and equivalent laws. You must have explicit written authorization before testing any target.

---

**SurfaceZero v2.1 | BinaryGalaxys Security | OSCP · OSEP · CRTP**
