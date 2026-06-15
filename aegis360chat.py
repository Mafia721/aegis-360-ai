#!/usr/bin/env python3
"""
aegis360chat.py — Fallback CLI for Aegis-360 AI
Use this ONLY when Claude Desktop / MCP is unavailable.

PRIMARY INTERFACE: Claude Desktop via aegis_360_mcp.py (MCP protocol).
All operator commands should flow through Claude Desktop. This CLI is a
last-resort fallback for terminal-only sessions.

Routing policy (matches server smart_chat):
  Exploitation tasks           → Claude Sonnet 4.6  (Anthropic API — PAID)
  Planning / Strategy          → DeepSeek V4 Pro    (OpenRouter — default)
  Code / PoC scripts           → DeepSeek V4 Pro    (OpenRouter — default)
  Recon / Enumeration          → DeepSeek V4 Pro    (OpenRouter — default)
  OSINT / Info gathering       → DeepSeek V4 Pro    (OpenRouter — default)
  Deep analysis                → DeepSeek V4 Pro    (OpenRouter — default)
  Fast lookups                 → DeepSeek V4 Pro    (OpenRouter — concise mode)
  Log / scan output parsing    → DeepSeek V4 Pro    (OpenRouter — default)

Usage (fallback only):
    python3 aegis360chat.py                           # auto-routing mode
    python3 aegis360chat.py --model deepseek          # lock to DeepSeek V4 Pro
    python3 aegis360chat.py --model claude            # lock to Claude API
    python3 aegis360chat.py --model all               # broadcast to all models
    python3 aegis360chat.py --list                    # show available models
    python3 aegis360chat.py --ask "question"          # one-shot
    python3 aegis360chat.py --agent "task"            # one-shot autonomous agent run
    python3 aegis360chat.py --recon example.com       # quick recon agent
"""

import os
import sys
import json
import threading
import argparse
import time
from pathlib import Path
from datetime import datetime

try:
    import requests as _requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

# Server default matches aegis_360_server.py port
AEGIS_360_SERVER = os.environ.get("AEGIS_360_SERVER", "http://127.0.0.1:8888")

# Load .env
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

try:
    from openai import OpenAI
    _OPENAI_OK = True
except ImportError:
    _OPENAI_OK = False

try:
    import anthropic as _ant
    _ANTHROPIC_OK = True
except ImportError:
    _ANTHROPIC_OK = False

# ── Colours ───────────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
C  = "\033[96m"
M  = "\033[95m"
W  = "\033[97m"
DIM= "\033[2m"
B  = "\033[1m"
X  = "\033[0m"

# ── Credentials ────────────────────────────────────────────────────────────────
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
ANT_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
OR_KEY   = (os.environ.get("OPENROUTER_API_KEY") or
            os.environ.get("DEEPSEEK_V4_PRO_KEY") or
            os.environ.get("QWEN_API_KEY", ""))
OR_URL   = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
DS_MODEL = os.environ.get("DEEPSEEK_V4_PRO_MODEL", "deepseek/deepseek-v4-pro")

# ── Model registry ─────────────────────────────────────────────────────────────
MODELS = {
    # ── Primary / default model ───────────────────────────────────────────────
    "deepseek": {
        "name":     f"DeepSeek V4 Pro ({DS_MODEL})",
        "provider": "OpenRouter",
        "model_id": DS_MODEL,
        "key":      OR_KEY,
        "base_url": OR_URL,
        "color":    C,
        "best_for": "Planning, code, recon, analysis, lookups — DEFAULT for all non-exploit tasks",
    },
    # ── Exploitation-only model ───────────────────────────────────────────────
    "claude": {
        "name":     "Claude Sonnet 4.6",
        "provider": "Anthropic API",
        "model_id": "claude-sonnet-4-6",
        "key":      ANT_KEY,
        "base_url": None,
        "color":    R,
        "best_for": "Exploitation planning & report generation (paid — post gate only)",
    },
    # ── Groq models — direct selection only (NOT used by auto-routing) ──────────
    # Auto-routing for all task categories uses DeepSeek V4 Pro exclusively.
    # These entries remain available for explicit --model <key> overrides only.
    "llama33": {
        "name":     "Llama 3.3 70B Versatile",
        "provider": "Groq",
        "model_id": "llama-3.3-70b-versatile",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    G,
        "best_for": "Direct selection only — auto-routing uses DeepSeek V4 Pro",
    },
    "llama4": {
        "name":     "Llama 4 Scout 17B",
        "provider": "Groq",
        "model_id": "meta-llama/llama-4-scout-17b-16e-instruct",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    C,
        "best_for": "Direct selection only — auto-routing uses DeepSeek V4 Pro",
    },
    "qwen3": {
        "name":     "Qwen3 32B",
        "provider": "Groq",
        "model_id": "qwen/qwen3-32b",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    Y,
        "best_for": "Direct selection only — auto-routing uses DeepSeek V4 Pro",
    },
    "gptoss": {
        "name":     "OpenAI OSS 120B",
        "provider": "Groq",
        "model_id": "openai/gpt-oss-120b",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    M,
        "best_for": "Direct selection only — auto-routing uses DeepSeek V4 Pro",
    },
    "fast": {
        "name":     "Llama 3.1 8B Instant",
        "provider": "Groq",
        "model_id": "llama-3.1-8b-instant",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    W,
        "best_for": "Direct selection only — auto-routing uses DeepSeek V4 Pro",
    },
}

SYSTEM_PROMPT = (
    "You are an expert offensive security assistant embedded in Aegis-360 AI, "
    "a professional penetration testing platform. You help authorised pentesters "
    "with vulnerability analysis, exploit development, attack chain planning, "
    "payload crafting, log analysis, and security research. "
    "Be direct, technical, and concise. When generating code, make it complete and working."
)

# ── Task router ─────────────────────────────────────────────────────────────────
EXPLOIT_KEYWORDS = [
    "exploit", "exploitation", "weaponize", "payload delivery", "execute exploit",
    "run exploit", "send payload", "trigger", "get shell", "reverse shell",
    "bind shell", "rce", "remote code execution", "privilege escalation", "privesc",
    "post exploitation", "lateral movement", "persistence", "exfiltrate",
    "bypass waf", "bypass auth", "authentication bypass", "sql injection attack",
    "xss attack", "command injection", "write exploit", "generate exploit",
    "buffer overflow", "rop chain", "shellcode", "metasploit", "msfvenom",
    "upload shell", "webshell", "backdoor",
]

# DeepSeek V4 Pro handles every non-exploit task type
TASK_ROUTING = {
    "planning":      ("deepseek", "Planning & strategy → DeepSeek V4 Pro"),
    "recon":         ("deepseek", "Recon & enumeration → DeepSeek V4 Pro"),
    "osint":         ("deepseek", "OSINT & info gathering → DeepSeek V4 Pro"),
    "crawl":         ("deepseek", "Web crawl & log parsing → DeepSeek V4 Pro"),
    "log_parse":     ("deepseek", "Scan output analysis → DeepSeek V4 Pro"),
    "code":          ("deepseek", "Code & PoC scripts → DeepSeek V4 Pro"),
    "analysis":      ("deepseek", "Deep analysis → DeepSeek V4 Pro"),
    "vuln_analysis": ("deepseek", "Vulnerability analysis → DeepSeek V4 Pro"),
    "quick":         ("deepseek", "Fast lookup → DeepSeek V4 Pro (concise)"),
    "enum":          ("deepseek", "Enumeration → DeepSeek V4 Pro"),
    "comms":         ("deepseek", "General → DeepSeek V4 Pro"),
}

TASK_KEYWORDS = {
    "planning":      ["plan", "strategy", "approach", "methodology", "roadmap",
                      "attack plan", "checklist", "what should i", "architecture",
                      "design", "tradeoff", "recommend"],
    "recon":         ["recon", "reconnaissance", "enumerate", "scan", "scanning",
                      "discover", "nmap", "subdomain", "port", "fingerprint"],
    "osint":         ["osint", "information gathering", "shodan", "whois", "dns",
                      "email harvest", "social media", "breach", "dork"],
    "crawl":         ["crawl", "crawler", "spider", "katana", "hakrawler",
                      "url", "endpoint", "route", "parse output", "parse result"],
    "log_parse":     ["log", "output", "result", "parse", "nmap output",
                      "nikto output", "nuclei output", "burp history", "scan output"],
    "code":          ["write code", "write script", "write tool", "generate code",
                      "python", "bash script", "poc", "proof of concept", "automate",
                      "implement", "function", "class", "snippet"],
    "analysis":      ["analyse", "analyze", "assess", "assessment", "review",
                      "explain", "how does", "why is", "cve", "research",
                      "root cause", "investigate", "compare", "deep dive"],
    "vuln_analysis": ["vulnerability", "vulnerabilities", "vuln", "triage",
                      "cvss", "severity", "risk rating", "exploitable",
                      "prioritize", "prioritise", "attack surface", "findings"],
    "quick":         ["what is", "define", "briefly", "tldr", "one line", "quick",
                      "short answer", "summarize", "summary"],
    "enum":          ["smb", "ftp", "ssh", "gobuster", "ffuf", "dirb", "wpscan",
                      "service version", "banner grab", "enumerate service"],
}

# Response format preambles injected per task type for DeepSeek V4 Pro
_TASK_PREAMBLES = {
    "planning":      "[MODE: Planning & Strategy] Think step-by-step. Structure your response as: Approach / Assumptions / Risks / Recommended Actions.",
    "code":          "[MODE: Code & PoC] Write production-quality code. Include setup instructions, dependencies, and testing steps.",
    "quick":         "[MODE: Fast Lookup] Be concise. Use bullet points. No extended analysis unless explicitly requested.",
    "analysis":      "[MODE: Deep Analysis] Structure response as: Executive Summary / Key Findings / Evidence / Risks / Recommendations / Next Steps.",
    "vuln_analysis": "[MODE: Vulnerability Analysis] Assign CVSS v3.1 scores. Prioritize by exploitability. Return structured findings.",
    "recon":         "[MODE: Reconnaissance] Recommend exact tool commands with optimised flags. Provide structured JSON findings.",
    "enum":          "[MODE: Enumeration] Recommend exact tool commands with flags. Return structured service findings.",
    "osint":         "[MODE: OSINT] Structure gathered intelligence clearly. Cite data sources.",
    "log_parse":     "[MODE: Log Analysis] Extract key findings from the provided output. Prioritize by severity.",
    "crawl":         "[MODE: Web Crawl Analysis] Parse endpoints and structure the findings.",
}


def auto_route(message: str) -> tuple:
    """
    Returns (model_key, reason, preamble).
    Exploitation → Claude.  Everything else → DeepSeek V4 Pro with task preamble.
    """
    msg = message.lower()
    if any(k in msg for k in EXPLOIT_KEYWORDS):
        return "claude", "Exploitation task → Claude Sonnet 4.6 (API)", ""

    scores = {task: sum(1 for kw in kws if kw in msg)
              for task, kws in TASK_KEYWORDS.items()}
    best = max(scores, key=scores.get) if max(scores.values()) > 0 else "comms"
    model, reason = TASK_ROUTING.get(best, ("deepseek", "General → DeepSeek V4 Pro"))
    preamble = _TASK_PREAMBLES.get(best, "")
    return model, reason, preamble


# ── Chat helpers ─────────────────────────────────────────────────────────────────

def call_openai_compat(key_id: str, history: list, max_tokens: int = 2048) -> dict:
    """Call any OpenAI-compatible endpoint (Groq, OpenRouter/DeepSeek)."""
    cfg = MODELS.get(key_id)
    if cfg is None:
        return {"key": key_id, "success": False, "error": f"Unknown model key: '{key_id}'"}
    if not cfg["key"]:
        return {"key": key_id, "success": False,
                "error": f"API key not set for {cfg['provider']} ({key_id})"}
    if not _OPENAI_OK:
        return {"key": key_id, "success": False, "error": "pip install openai"}
    try:
        client = OpenAI(api_key=cfg["key"], base_url=cfg["base_url"])
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}] + history
        resp = client.chat.completions.create(
            model=cfg["model_id"], max_tokens=max_tokens, messages=msgs)
        return {"key": key_id, "success": True,
                "response": resp.choices[0].message.content}
    except Exception as e:
        return {"key": key_id, "success": False, "error": str(e)}


def call_claude(history: list, max_tokens: int = 2048) -> dict:
    if not ANT_KEY or not _ANTHROPIC_OK:
        return {"key": "claude", "success": False, "error": "ANTHROPIC_API_KEY not set"}
    try:
        client = _ant.Anthropic(api_key=ANT_KEY)
        msgs = [{"role": m["role"], "content": m["content"]}
                for m in history if m["role"] in ("user", "assistant")]
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=max_tokens,
            system=[{"type": "text", "text": SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            messages=msgs,
        )
        text = next((b.text for b in resp.content if b.type == "text"), "")
        return {"key": "claude", "success": True, "response": text}
    except _ant.AuthenticationError:
        return {"key": "claude", "success": False, "error": "API key invalid or missing"}
    except _ant.RateLimitError:
        return {"key": "claude", "success": False, "error": "Rate limit hit — retry later"}
    except _ant.APIError as e:
        return {"key": "claude", "success": False, "error": f"API error {e.status_code}: {e.message}"}


def call_model(key_id: str, history: list, max_tokens: int = 2048) -> dict:
    """Dispatch to the right backend based on model key."""
    if key_id == "claude":
        return call_claude(history, max_tokens)
    return call_openai_compat(key_id, history, max_tokens)


def call_all(history: list, max_tokens: int = 2048) -> list:
    """Broadcast to DeepSeek V4 Pro + all Groq free models concurrently."""
    broadcast_keys = [k for k in MODELS if k != "claude"]
    results = [None] * len(broadcast_keys)

    def worker(i, k):
        results[i] = call_model(k, history, max_tokens)

    threads = [threading.Thread(target=worker, args=(i, k))
               for i, k in enumerate(broadcast_keys)]
    for t in threads: t.start()
    for t in threads: t.join()
    return [r for r in results if r]


def call_agent(task: str, model: str = "auto", context: str = "",
               max_iter: int = 10) -> dict:
    """Call the aegis_360_server ReAct agent loop."""
    if not _REQUESTS_OK:
        return {"success": False, "error": "pip install requests to use agent mode"}
    try:
        resp = _requests.post(
            f"{AEGIS_360_SERVER}/api/agent/run",
            json={"task": task, "model": model if model != "auto" else "",
                  "context": context, "max_iter": max_iter},
            timeout=600,
        )
        return resp.json()
    except _requests.exceptions.ConnectionError:
        return {"success": False,
                "error": f"Server not reachable at {AEGIS_360_SERVER} — run: python3 aegis_360_server.py"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


# ── Display ───────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{R}{B}╔══════════════════════════════════════════════════════════════╗
║         Aegis-360 AI — Fallback CLI                          ║
║   Use Claude Desktop (MCP) as primary interface              ║
║   DeepSeek V4 Pro: default  |  Claude API: exploitation only ║
╚══════════════════════════════════════════════════════════════╝{X}

{B}Available models:{X}
""")
    for k, cfg in MODELS.items():
        avail = f"{G}✅ live{X}" if cfg["key"] else f"{R}❌ no key{X}"
        marker = f" {Y}← DEFAULT{X}" if k == "deepseek" else ""
        print(f"  {cfg['color']}{B}{k:<10}{X}  {cfg['name']:<40} {avail}{marker}")
        print(f"  {DIM}{'':10}  {cfg['best_for']}{X}")
    print(f"""
{B}Commands:{X}
  {Y}/model <key>{X}           switch model  (e.g. /model deepseek)
  {Y}/all{X}                   broadcast to all models
  {Y}/auto{X}                  enable auto-routing (DeepSeek default)
  {Y}/clear{X}                 clear conversation history
  {Y}/list{X}                  show models again
  {Y}/agent <task>{X}          run autonomous agent
  {Y}/recon <target>{X}        run recon agent on domain/IP
  {Y}/vuln <target>{X}         run vulnerability hunting agent
  {Y}/exploit <target> <desc>{X}  run Claude exploitation agent
  {Y}/exit{X}                  quit
""")


def print_response(key_id: str, text: str):
    cfg = MODELS.get(key_id, {})
    color = cfg.get("color", W)
    name  = cfg.get("name", key_id)
    ts    = datetime.now().strftime("%H:%M:%S")
    print(f"\n{color}{B}[{name}]{X} {DIM}{ts}{X}")
    print(f"{color}{'─'*60}{X}")
    print(text.strip())
    print(f"{color}{'─'*60}{X}\n")


def print_agent_result(result: dict):
    if not result.get("success"):
        print(f"\n{R}[AGENT ERROR] {result.get('error', 'Unknown error')}{X}\n")
        return

    model_id = result.get("model_id", result.get("model_key", "?"))
    iters    = result.get("iterations", 0)
    trace    = result.get("trace", [])
    response = result.get("response", "")

    print(f"\n{M}{B}╔══ AGENT RESULT ══════════════════════════════════════╗{X}")
    print(f"{M}  Model:      {W}{model_id}{X}")
    print(f"{M}  Iterations: {W}{iters}{X}")

    if trace:
        print(f"\n{B}  Tool calls:{X}")
        for step in trace:
            tool = step.get("tool")
            if tool:
                args_preview = str(step.get("args", {}))[:80]
                result_prev  = step.get("result_preview", "")[:120].replace("\n", " ")
                print(f"  {DIM}[iter {step.get('iteration','')}]{X} {C}{tool}{X}({Y}{args_preview}{X})")
                if result_prev:
                    print(f"  {DIM}    → {result_prev}{X}")

    print(f"\n{M}{B}╔══ FINAL REPORT ══════════════════════════════════════╗{X}")
    print(f"{W}{response.strip()}{X}")
    print(f"{M}{B}╚══════════════════════════════════════════════════════╝{X}\n")


def list_models():
    print(f"\n{B}Models:{X}")
    for k, cfg in MODELS.items():
        avail  = f"{G}✅{X}" if cfg["key"] else f"{R}❌{X}"
        marker = f" {Y}← DEFAULT{X}" if k == "deepseek" else ""
        print(f"  {cfg['color']}{k:<10}{X}  {cfg['name']}  {avail}  — {cfg['best_for']}{marker}")
    print()


# ── Main REPL ──────────────────────────────────────────────────────────────────

def run_repl(default_model: str = "auto"):
    banner()
    history   = []
    model_key = default_model
    broadcast = False
    auto_mode = (default_model == "auto")

    if model_key not in MODELS and model_key not in ("all", "auto"):
        print(f"{R}Unknown model '{model_key}'. Valid: {', '.join(MODELS)} | all | auto{X}")
        model_key = "auto"
        auto_mode = True

    if auto_mode:
        print(f"{G}{B}Mode: AUTO-ROUTING{X}  {DIM}— DeepSeek V4 Pro default | Claude for exploitation{X}\n")
    else:
        cfg = MODELS.get(model_key, {})
        print(f"{G}Active model: {B}{cfg.get('name', model_key)}{X}  "
              f"{DIM}(type /auto to enable auto-routing){X}\n")

    while True:
        try:
            prompt = input(f"{Y}{B}you>{X} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{DIM}Bye.{X}")
            break

        if not prompt:
            continue

        # ── Commands ─────────────────────────────────────────────────────────
        if prompt.lower() in ("/exit", "/quit", "exit", "quit"):
            print(f"{DIM}Bye.{X}")
            break

        if prompt.lower() == "/list":
            list_models()
            continue

        if prompt.lower() == "/clear":
            history = []
            print(f"{G}History cleared.{X}\n")
            continue

        if prompt.lower() == "/all":
            broadcast = True
            print(f"{C}Next message → all models.{X}\n")
            continue

        if prompt.lower() == "/auto":
            auto_mode = True
            model_key = "auto"
            print(f"{G}Auto-routing enabled.{X} {DIM}DeepSeek V4 Pro default.{X}\n")
            continue

        if prompt.lower().startswith("/model "):
            new_key = prompt.split()[1].lower()
            if new_key not in MODELS:
                print(f"{R}Unknown model. Choose: {', '.join(MODELS)}{X}\n")
            else:
                model_key = new_key
                auto_mode = False
                cfg = MODELS[model_key]
                print(f"{G}Switched to: {B}{cfg['name']}{X} {DIM}(auto-routing off){X}\n")
            continue

        # ── Agent commands ────────────────────────────────────────────────────
        if prompt.lower().startswith("/agent "):
            task = prompt[7:].strip()
            if not task:
                print(f"{R}Usage: /agent <task description>{X}\n")
                continue
            is_exploit  = any(k in task.lower() for k in EXPLOIT_KEYWORDS)
            agent_model = "claude" if is_exploit else "deepseek-v4-pro"
            cost_note   = f"{R}Claude API (paid){X}" if is_exploit else f"{C}DeepSeek V4 Pro{X}"
            print(f"\n{M}🤖 Agent running... [{cost_note}]{X}")
            print(f"{DIM}Task: {task[:80]}{X}\n")
            result = call_agent(task, model=agent_model)
            print_agent_result(result)
            continue

        if prompt.lower().startswith("/recon "):
            target = prompt[7:].strip()
            if not target:
                print(f"{R}Usage: /recon <domain_or_ip>{X}\n")
                continue
            task = (
                f"Perform comprehensive reconnaissance on: {target}\n"
                f"Run subfinder for subdomains, nmap for ports, httpx to probe live hosts, "
                f"katana to crawl web endpoints, waybackurls for historical URLs, "
                f"and nuclei with info/exposure templates. Return a full recon report."
            )
            print(f"\n{C}🔍 Recon agent running on {B}{target}{X}{C}...{X} {DIM}(DeepSeek V4 Pro){X}\n")
            result = call_agent(task, model="deepseek-v4-pro")
            print_agent_result(result)
            continue

        if prompt.lower().startswith("/vuln "):
            target = prompt[6:].strip()
            if not target:
                print(f"{R}Usage: /vuln <target_url>{X}\n")
                continue
            task = (
                f"Find vulnerabilities on: {target}\n"
                f"Run nuclei (critical/high), nikto, gobuster, dalfox for XSS, "
                f"ffuf for parameter fuzzing, and sqlmap if SQLi indicators found. "
                f"Return a vulnerability report with severity and PoC evidence."
            )
            print(f"\n{Y}🐛 Vulnerability agent running on {B}{target}{X}{Y}...{X} {DIM}(DeepSeek V4 Pro){X}\n")
            result = call_agent(task, model="deepseek-v4-pro", max_iter=15)
            print_agent_result(result)
            continue

        if prompt.lower().startswith("/exploit "):
            parts  = prompt[9:].strip().split(None, 1)
            target = parts[0] if parts else ""
            vuln   = parts[1] if len(parts) > 1 else ""
            if not target or not vuln:
                print(f"{R}Usage: /exploit <target> <vulnerability description>{X}\n")
                continue
            task = (
                f"Exploit the following on {target}: {vuln}\n"
                f"Confirm it is real, develop a working PoC, execute it, capture evidence, "
                f"assess impact and escalation path."
            )
            print(f"\n{R}💥 Exploit agent on {B}{target}{X}{R}...{X} {R}[Claude API — paid]{X}\n")
            result = call_agent(task, model="claude")
            print_agent_result(result)
            continue

        # ── Chat ─────────────────────────────────────────────────────────────
        history.append({"role": "user", "content": prompt})

        if broadcast or model_key == "all":
            broadcast = False
            print(f"{C}Broadcasting to {len(MODELS)} models...{X}")
            results = call_all(history)
            assistant_text = []
            for r in results:
                if r["success"]:
                    print_response(r["key"], r["response"])
                    assistant_text.append(f"[{r['key']}]: {r['response']}")
                else:
                    print(f"{R}[{r['key']}] Error: {r['error']}{X}\n")
            if assistant_text:
                history.append({"role": "assistant",
                                "content": "\n\n".join(assistant_text)})

        elif auto_mode:
            chosen, reason, preamble = auto_route(prompt)
            cfg = MODELS.get(chosen, {})
            cost = (f"{R}Claude API (paid){X}" if chosen == "claude"
                    else f"{C}OpenRouter (DeepSeek V4 Pro){X}")
            print(f"{DIM}→ {cfg.get('name', chosen)} | {reason} | {cost}{X}")

            # Apply task-type preamble for DeepSeek — update last history entry
            if preamble and chosen == "deepseek":
                history[-1]["content"] = f"{preamble}\n\n{prompt}"

            r = call_model(chosen, history)
            if r["success"]:
                print_response(chosen, r["response"])
                # Store original prompt in history, not the preamble-prefixed one
                history[-1]["content"] = prompt
                history.append({"role": "assistant", "content": r["response"]})
            else:
                print(f"{R}Error: {r['error']}{X}\n")
                history.pop()

        else:
            print(f"{DIM}Asking {MODELS.get(model_key,{}).get('name', model_key)}...{X}")
            r = call_model(model_key, history)
            if r["success"]:
                print_response(model_key, r["response"])
                history.append({"role": "assistant", "content": r["response"]})
            else:
                print(f"{R}Error: {r['error']}{X}\n")
                history.pop()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Aegis360 multi-model chat CLI")
    parser.add_argument("--model", default="auto",
                        help=f"Model: auto (default) | {' | '.join(MODELS)} | all")
    parser.add_argument("--list",   action="store_true", help="List models and exit")
    parser.add_argument("--ask",    metavar="QUESTION",  help="One-shot question")
    parser.add_argument("--agent",  metavar="TASK",      help="Run autonomous agent on TASK")
    parser.add_argument("--recon",  metavar="TARGET",    help="Run recon agent on domain/IP")
    parser.add_argument("--vuln",   metavar="TARGET",    help="Run vulnerability agent on URL")
    parser.add_argument("--max-iter", type=int, default=10, help="Agent max iterations (default 10)")
    args = parser.parse_args()

    if args.list:
        list_models()
        return

    if args.ask:
        history = [{"role": "user", "content": args.ask}]
        if args.model == "all":
            results = call_all(history)
            for r in results:
                if r["success"]:
                    print(f"\n[{r['key']}]:\n{r['response']}\n")
                else:
                    print(f"[{r['key']}] ERROR: {r['error']}")
        elif args.model == "auto":
            chosen, reason, preamble = auto_route(args.ask)
            if preamble and chosen == "deepseek":
                history[0]["content"] = f"{preamble}\n\n{args.ask}"
            r = call_model(chosen, history)
            if r["success"]:
                print(r["response"])
            else:
                print(f"ERROR: {r['error']}", file=sys.stderr)
                sys.exit(1)
        else:
            r = call_model(args.model, history)
            if r["success"]:
                print(r["response"])
            else:
                print(f"ERROR: {r['error']}", file=sys.stderr)
                sys.exit(1)
        return

    if args.agent:
        is_exploit = any(k in args.agent.lower() for k in EXPLOIT_KEYWORDS)
        if args.model != "auto":
            m = args.model
        else:
            m = "claude" if is_exploit else "deepseek-v4-pro"
        print(f"\n🤖 Agent running... model={m}\nTask: {args.agent}\n")
        result = call_agent(args.agent, model=m, max_iter=args.max_iter)
        print_agent_result(result)
        return

    if args.recon:
        task = (
            f"Perform comprehensive reconnaissance on: {args.recon}\n"
            f"Run subfinder for subdomains, nmap for ports, httpx to probe live hosts, "
            f"katana to crawl web endpoints, waybackurls for historical URLs, "
            f"and nuclei with info/exposure templates. Return a full recon report."
        )
        print(f"\n🔍 Recon agent on {args.recon}... (DeepSeek V4 Pro)\n")
        result = call_agent(task, model="deepseek-v4-pro", max_iter=args.max_iter)
        print_agent_result(result)
        return

    if args.vuln:
        task = (
            f"Find vulnerabilities on: {args.vuln}\n"
            f"Run nuclei (critical/high), nikto, gobuster, dalfox for XSS, "
            f"ffuf for parameter fuzzing, and sqlmap if SQLi indicators found. "
            f"Return a vulnerability report with severity and PoC evidence."
        )
        print(f"\n🐛 Vuln agent on {args.vuln}... (DeepSeek V4 Pro)\n")
        result = call_agent(task, model="deepseek-v4-pro", max_iter=args.max_iter)
        print_agent_result(result)
        return

    run_repl(default_model=args.model)


if __name__ == "__main__":
    main()
