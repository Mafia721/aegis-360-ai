#!/usr/bin/env python3
"""
hexchat.py — FALLBACK CLI for Aegis-360 AI
Use this ONLY when Claude Desktop / MCP is unavailable.

PRIMARY INTERFACE: Claude Desktop via aegis_360_mcp.py (MCP protocol).
All operator commands should flow through Claude Desktop. This CLI is a
last-resort fallback for terminal-only sessions.

Routing policy (same as MCP layer):
  Exploitation tasks  → Claude Sonnet 4.6  (Anthropic API, PAID — exploitation ONLY)
  Planning/Strategy   → Llama 3.3 70B      (Groq, FREE)
  Recon/Enumeration   → Llama 3.3 / Llama4 (Groq, FREE)
  OSINT/Info gather   → OpenAI OSS 120B    (Groq, FREE)
  Crawl/Log parsing   → Qwen3 32B          (Groq, FREE)
  Code/PoC writing    → Qwen3 32B          (Groq, FREE)
  Deep analysis       → OpenAI OSS 120B    (Groq, FREE)
  Quick lookups       → Llama 3.1 8B       (Groq, FREE)

Usage (fallback only):
    python3 hexchat.py                      # auto-routing mode
    python3 hexchat.py --model llama33      # lock to one free model
    python3 hexchat.py --model all          # broadcast to all FREE Groq models
    python3 hexchat.py --list               # show available models
    python3 hexchat.py --ask "question"     # one-shot
    python3 hexchat.py --agent "task"       # one-shot autonomous agent run
    python3 hexchat.py --recon example.com  # quick recon agent
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

AEGIS_360_SERVER = os.environ.get("AEGIS_360_SERVER", "http://127.0.0.1:8000")

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

# ── Model registry ─────────────────────────────────────────────────────────────
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
ANT_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
OR_KEY   = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("QWEN_API_KEY", "")
OR_URL   = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

MODELS = {
    "llama33": {
        "name":     "Llama 3.3 70B Versatile",
        "provider": "Groq",
        "model_id": "llama-3.3-70b-versatile",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    G,
        "best_for": "General reasoning, pentest strategy, vulnerability analysis",
    },
    "llama4": {
        "name":     "Llama 4 Scout 17B",
        "provider": "Groq",
        "model_id": "meta-llama/llama-4-scout-17b-16e-instruct",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    C,
        "best_for": "Deep analysis, Meta latest model",
    },
    "qwen3": {
        "name":     "Qwen3 32B",
        "provider": "Groq",
        "model_id": "qwen/qwen3-32b",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    Y,
        "best_for": "Exploit code, PoC scripts, custom tools",
    },
    "gptoss": {
        "name":     "OpenAI OSS 120B",
        "provider": "Groq",
        "model_id": "openai/gpt-oss-120b",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    M,
        "best_for": "Largest free model, deep thorough analysis",
    },
    "fast": {
        "name":     "Llama 3.1 8B Instant",
        "provider": "Groq",
        "model_id": "llama-3.1-8b-instant",
        "key":      GROQ_KEY,
        "base_url": GROQ_URL,
        "color":    W,
        "best_for": "Ultra-fast, quick lookups, rapid iteration",
    },
    "claude": {
        "name":     "Claude Sonnet 4.6",
        "provider": "Anthropic API",
        "model_id": "claude-sonnet-4-6",
        "key":      ANT_KEY,
        "base_url": None,
        "color":    R,
        "best_for": "Best reasoning, exploitation planning (costs API credits)",
    },
}

SYSTEM_PROMPT = (
    "You are an expert offensive security assistant embedded in Aegis-360 AI, "
    "a professional penetration testing platform. You help authorised pentesters "
    "with vulnerability analysis, exploit development, attack chain planning, "
    "payload crafting, log analysis, and security research. "
    "Be direct, technical, and concise. When generating code, make it complete and working."
)

# ── Task router ────────────────────────────────────────────────────────────────

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

TASK_ROUTING = {
    "planning":  ("llama33", "Attack planning & strategy"),
    "recon":     ("llama33", "Recon & enumeration planning"),
    "osint":     ("gptoss",  "OSINT & info gathering"),
    "crawl":     ("qwen3",   "Web crawl & log parsing"),
    "log_parse": ("qwen3",   "Log/output parsing"),
    "code":      ("qwen3",   "Code & PoC writing"),
    "analysis":  ("gptoss",  "Deep analysis"),
    "quick":     ("fast",    "Quick lookup"),
    "enum":      ("llama4",  "Enumeration & service analysis"),
    "comms":     ("llama33", "General communication"),
}

TASK_KEYWORDS = {
    "planning":  ["plan", "strategy", "approach", "methodology", "roadmap",
                  "attack plan", "checklist", "what should i"],
    "recon":     ["recon", "reconnaissance", "enumerate", "scan", "scanning",
                  "discover", "nmap", "subdomain", "port", "fingerprint"],
    "osint":     ["osint", "information gathering", "shodan", "whois", "dns",
                  "email harvest", "social media", "breach", "dork"],
    "crawl":     ["crawl", "crawler", "spider", "katana", "hakrawler",
                  "url", "endpoint", "route", "parse output", "parse result"],
    "log_parse": ["log", "output", "result", "parse", "nmap output",
                  "nikto output", "nuclei output", "burp history", "scan output"],
    "code":      ["write code", "write script", "write tool", "generate code",
                  "python", "bash script", "poc", "proof of concept", "automate"],
    "analysis":  ["analyse", "analyze", "assess", "assessment", "review",
                  "explain", "how does", "why is", "cve", "research"],
    "quick":     ["what is", "define", "briefly", "tldr", "one line", "quick"],
    "enum":      ["smb", "ftp", "ssh", "gobuster", "ffuf", "dirb", "wpscan",
                  "service version", "banner grab"],
}

def auto_route(message: str) -> tuple:
    """Returns (model_key, reason) based on message content."""
    msg = message.lower()
    if any(k in msg for k in EXPLOIT_KEYWORDS):
        return "claude", "Exploitation task → Claude Sonnet 4.6 (API)"
    scores = {task: sum(1 for kw in kws if kw in msg)
              for task, kws in TASK_KEYWORDS.items()}
    best = max(scores, key=scores.get) if max(scores.values()) > 0 else "comms"
    model, reason = TASK_ROUTING.get(best, ("llama33", "General query"))
    return model, reason


# ── Chat helpers ────────────────────────────────────────────────────────────────

def call_groq_model(key_id: str, history: list, max_tokens: int = 2048) -> dict:
    cfg = MODELS[key_id]
    if not cfg["key"] or not _OPENAI_OK:
        return {"key": key_id, "success": False, "error": "Not configured"}
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
    if key_id == "claude":
        return call_claude(history, max_tokens)
    return call_groq_model(key_id, history, max_tokens)


def call_all(history: list, max_tokens: int = 2048) -> list:
    # Broadcast to FREE Groq models only — Claude reserved for exploitation tasks
    free_keys = [k for k in MODELS.keys() if k != "claude"]
    results = [None] * len(free_keys)

    def worker(i, k):
        results[i] = call_model(k, history, max_tokens)

    threads = [threading.Thread(target=worker, args=(i, k))
               for i, k in enumerate(free_keys)]
    for t in threads: t.start()
    for t in threads: t.join()
    return [r for r in results if r]


def call_agent(task: str, model: str = "auto", context: str = "",
               max_iter: int = 10) -> dict:
    """Call the aegis_360_server ReAct agent loop directly."""
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
        return {"success": False, "error": f"aegis_360_server not reachable at {AEGIS_360_SERVER} — run: python3 aegis_360_server.py"}
    except Exception as exc:
        return {"success": False, "error": str(exc)}

# ── Display ────────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{R}{B}╔══════════════════════════════════════════════════════╗
║         Aegis-360 AI — Fallback CLI                  ║
║   Use Claude Desktop (MCP) as primary interface      ║
║   Claude API: exploitation only | Groq: everything   ║
╚══════════════════════════════════════════════════════╝{X}

{B}Available models:{X}
""")
    for k, cfg in MODELS.items():
        avail = f"{G}✅ live{X}" if cfg["key"] else f"{R}❌ no key{X}"
        print(f"  {cfg['color']}{B}{k:<10}{X}  {cfg['name']:<28} {avail}")
        print(f"  {DIM}{'':10}  {cfg['best_for']}{X}")
    print(f"""
{B}Commands:{X}
  {Y}/model <key>{X}          switch model  (e.g. /model qwen3)
  {Y}/all{X}                  broadcast next message to all models
  {Y}/auto{X}                 enable auto-routing
  {Y}/clear{X}                clear conversation history
  {Y}/list{X}                 show models again
  {Y}/agent <task>{X}         run autonomous agent (auto-selects model + tools)
  {Y}/recon <target>{X}       run recon agent on domain/IP
  {Y}/vuln <target>{X}        run vulnerability hunting agent on URL
  {Y}/exploit <target> <desc>{X}  run Claude exploitation agent
  {Y}/exit{X}                 quit
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
        avail = f"{G}✅{X}" if cfg["key"] else f"{R}❌{X}"
        print(f"  {cfg['color']}{k:<10}{X}  {cfg['name']}  {avail}  — {cfg['best_for']}")
    print()

# ── Main REPL ──────────────────────────────────────────────────────────────────

def run_repl(default_model: str = "auto"):
    banner()
    history   = []
    model_key = default_model
    broadcast = False
    auto_mode = (default_model == "auto")

    if model_key not in MODELS and model_key not in ("all", "auto"):
        print(f"{R}Unknown model '{model_key}'. Using auto-routing.{X}")
        model_key = "auto"
        auto_mode = True

    if auto_mode:
        print(f"{G}{B}Mode: AUTO-ROUTING{X}  {DIM}— model selected per task type{X}")
        print(f"{DIM}Exploitation → Claude (API) | Planning/Recon/Code → Groq (free){X}\n")
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

        # ── Commands ──────────────────────────────────────────────────────────
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
            print(f"{C}Next message will be broadcast to ALL models.{X}\n")
            continue

        if prompt.lower() == "/auto":
            auto_mode = True
            model_key = "auto"
            print(f"{G}Auto-routing enabled.{X} {DIM}Model selected per task type.{X}\n")
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
            is_exploit = any(k in task.lower() for k in EXPLOIT_KEYWORDS)
            agent_model = "claude" if is_exploit else "auto"
            cost_note = f"{R}Claude API (paid){X}" if is_exploit else f"{G}Groq free{X}"
            print(f"\n{M}🤖 Autonomous agent running... [{cost_note}]{X}")
            print(f"{DIM}Task: {task[:80]}...{X}\n")
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
                f"and nuclei with info/exposure templates. "
                f"Return a full recon report."
            )
            print(f"\n{C}🔍 Recon agent running on {B}{target}{X}{C}...{X} {DIM}(Groq free){X}\n")
            result = call_agent(task, model="llama33")
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
            print(f"\n{Y}🐛 Vulnerability agent running on {B}{target}{X}{Y}...{X} {DIM}(Groq free){X}\n")
            result = call_agent(task, model="llama33", max_iter=15)
            print_agent_result(result)
            continue

        if prompt.lower().startswith("/exploit "):
            parts   = prompt[9:].strip().split(None, 1)
            target  = parts[0] if parts else ""
            vuln    = parts[1] if len(parts) > 1 else ""
            if not target or not vuln:
                print(f"{R}Usage: /exploit <target> <vulnerability description>{X}\n")
                continue
            task = (
                f"Exploit the following on {target}: {vuln}\n"
                f"Confirm it is real, develop a working PoC, execute it, capture evidence, "
                f"assess impact and escalation path."
            )
            print(f"\n{R}💥 Exploit agent running on {B}{target}{X}{R}...{X} {R}[Claude API — paid]{X}\n")
            result = call_agent(task, model="claude")
            print_agent_result(result)
            continue

        # ── Chat ──────────────────────────────────────────────────────────────
        history.append({"role": "user", "content": prompt})

        if broadcast or model_key == "all":
            broadcast = False
            print(f"{C}Broadcasting to all {len(MODELS)} models...{X}")
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
            chosen, reason = auto_route(prompt)
            cfg = MODELS.get(chosen, {})
            cost = f"{R}Claude API (paid){X}" if chosen == "claude" else f"{G}Groq (free){X}"
            print(f"{DIM}→ {cfg.get('name', chosen)} | {reason} | {cost}{X}")
            r = call_model(chosen, history)
            if r["success"]:
                print_response(chosen, r["response"])
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
                        help=f"Model key: auto (default) | {' | '.join(MODELS.keys())} | all")
    parser.add_argument("--list",   action="store_true", help="List models and exit")
    parser.add_argument("--ask",    metavar="QUESTION",  help="One-shot question (non-interactive)")
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
        m = "claude" if is_exploit else (args.model if args.model != "auto" else "")
        print(f"\n🤖 Agent running... model={m or 'auto'}\nTask: {args.agent}\n")
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
        print(f"\n🔍 Recon agent running on {args.recon}...\n")
        result = call_agent(task, model="llama33", max_iter=args.max_iter)
        print_agent_result(result)
        return

    if args.vuln:
        task = (
            f"Find vulnerabilities on: {args.vuln}\n"
            f"Run nuclei (critical/high), nikto, gobuster, dalfox for XSS, "
            f"ffuf for parameter fuzzing, and sqlmap if SQLi indicators found. "
            f"Return a vulnerability report with severity and PoC evidence."
        )
        print(f"\n🐛 Vuln agent running on {args.vuln}...\n")
        result = call_agent(task, model="llama33", max_iter=args.max_iter)
        print_agent_result(result)
        return

    run_repl(default_model=args.model)


if __name__ == "__main__":
    main()
