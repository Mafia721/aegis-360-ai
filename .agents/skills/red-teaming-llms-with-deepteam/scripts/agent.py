#!/usr/bin/env python3
"""
DeepTeam red-team automation helper for Aegis-360.

Wraps the Aegis-360 /api/deepteam/* endpoints to run adversarial LLM scans,
poll async jobs, and display scored vulnerability results. Use only against
models and endpoints you are authorized to test.

Examples:
  # Synchronous scan via HTTP endpoint
  python agent.py scan --endpoint http://your-llm/chat \
      --purpose "customer support bot" \
      --vulns "Toxicity,PIILeakage,PromptLeakage" \
      --attacks "PromptInjection,Roleplay"

  # Async scan via OpenAI model with polling
  python agent.py scan-async --model gpt-4o-mini --api-key $OPENAI_API_KEY \
      --vulns "SQLInjection,SSRF,ShellInjection" \
      --attacks "SystemOverride,LinearJailbreaking" --poll

  # List all jobs
  python agent.py jobs

  # Fetch a completed report
  python agent.py report --job-id <job_id>

  # List capabilities
  python agent.py list-vulnerabilities
  python agent.py list-attacks
"""
import argparse
import json
import sys
import time
from typing import Any, Dict

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

DEFAULT_SERVER = "http://127.0.0.1:8888"


def _api(server: str, method: str, path: str, **kwargs) -> Dict[str, Any]:
    url = f"{server.rstrip('/')}/{path.lstrip('/')}"
    try:
        resp = getattr(requests, method)(url, timeout=120, **kwargs)
        resp.raise_for_status()
        return resp.json()
    except requests.ConnectionError:
        sys.exit(f"[!] Cannot reach Aegis-360 server at {server} — is it running?")
    except requests.HTTPError as exc:
        try:
            detail = exc.response.json()
        except Exception:
            detail = exc.response.text
        sys.exit(f"[!] API error {exc.response.status_code}: {detail}")
    except Exception as exc:
        sys.exit(f"[!] Request failed: {exc}")


def _print_results(result: Dict[str, Any]):
    """Print scan results in a readable format."""
    status = result.get("status", "unknown")
    print(f"\n[*] Job status: {status}")

    if "error" in result:
        print(f"[!] Error: {result['error']}")
        return

    res = result.get("result")
    if not res:
        print("[*] No results yet.")
        print(json.dumps({k: v for k, v in result.items() if k not in ("result",)}, indent=2))
        return

    # Try to render structured results
    if isinstance(res, dict):
        test_cases = (
            res.get("test_cases")
            or res.get("results")
            or res.get("red_team_results")
            or []
        )
        if test_cases:
            print(f"\n{'─'*72}")
            print(f"{'VULN':<30} {'ATTACK':<28} {'PASSED':<8} SCORE")
            print(f"{'─'*72}")
            passed_count = failed_count = 0
            for tc in test_cases:
                vuln = str(tc.get("vulnerability", tc.get("vulnerability_type", "?")))[:29]
                attack = str(tc.get("attack", tc.get("attack_type", "?")))[:27]
                passed = tc.get("passed", tc.get("success", "?"))
                score = tc.get("score", "?")
                marker = "✓" if passed else "✗"
                if passed is True:
                    passed_count += 1
                elif passed is False:
                    failed_count += 1
                print(f"{vuln:<30} {attack:<28} {marker:<8} {score}")
            total = passed_count + failed_count
            print(f"{'─'*72}")
            if total:
                rate = failed_count / total * 100
                print(f"Failures: {failed_count}/{total}  ({rate:.1f}% vulnerability rate)")
        else:
            print(json.dumps(res, indent=2, default=str))
    else:
        print(json.dumps(res, indent=2, default=str))


def cmd_scan(args):
    if not args.endpoint and not args.model:
        sys.exit("[!] Provide --endpoint or --model")

    payload = {
        "endpoint_url": args.endpoint or "",
        "model": args.model or "",
        "api_key": args.api_key or "",
        "base_url": args.base_url or "",
        "system_prompt": args.system_prompt or "",
        "target_purpose": args.purpose or "",
        "vulnerabilities": args.vulns or "Toxicity,PIILeakage,PromptLeakage",
        "attacks": args.attacks or "PromptInjection,Roleplay",
        "attacks_per_vulnerability": args.attacks_per_vuln,
        "simulator_model": args.simulator_model,
        "evaluation_model": args.evaluation_model,
        "max_concurrent": args.max_concurrent,
        "scan_timeout": args.timeout,
    }
    print(f"[*] Starting synchronous DeepTeam scan (timeout: {args.timeout}s)…")
    result = _api(args.server, "post", "/api/deepteam/scan", json=payload)
    _print_results(result)


def cmd_scan_async(args):
    if not args.endpoint and not args.model:
        sys.exit("[!] Provide --endpoint or --model")

    payload = {
        "endpoint_url": args.endpoint or "",
        "model": args.model or "",
        "api_key": args.api_key or "",
        "base_url": args.base_url or "",
        "system_prompt": args.system_prompt or "",
        "target_purpose": args.purpose or "",
        "vulnerabilities": args.vulns or "Toxicity,PIILeakage,PromptLeakage",
        "attacks": args.attacks or "PromptInjection,Roleplay",
        "attacks_per_vulnerability": args.attacks_per_vuln,
        "simulator_model": args.simulator_model,
        "evaluation_model": args.evaluation_model,
        "max_concurrent": args.max_concurrent,
    }
    result = _api(args.server, "post", "/api/deepteam/scan-async", json=payload)
    job_id = result.get("job_id", "")
    print(f"[*] Scan submitted — job_id: {job_id}")

    if not args.poll or not job_id:
        return

    print("[*] Polling for completion…")
    interval = 15
    while True:
        time.sleep(interval)
        status_result = _api(args.server, "get", f"/api/deepteam/status/{job_id}")
        status = status_result.get("status", "unknown")
        progress = status_result.get("progress", "")
        print(f"    [{status}] {progress}")
        if status in ("completed", "failed"):
            _print_results(status_result)
            break
        interval = min(interval + 10, 60)


def cmd_status(args):
    result = _api(args.server, "get", f"/api/deepteam/status/{args.job_id}")
    print(json.dumps(result, indent=2, default=str))


def cmd_report(args):
    result = _api(args.server, "get", f"/api/deepteam/report/{args.job_id}")
    _print_results(result)


def cmd_jobs(args):
    result = _api(args.server, "get", "/api/deepteam/jobs")
    jobs = result.get("jobs", {})
    if not jobs:
        print("[*] No jobs found.")
        return
    print(f"\n{'JOB ID':<38} {'STATUS':<12} {'TARGET':<40} UPDATED")
    print("─" * 110)
    for jid, info in sorted(jobs.items(), key=lambda x: x[1].get("updated_at", "")):
        status = info.get("status", "?")
        summary = info.get("params_summary", {})
        target = (summary.get("endpoint_url") or summary.get("target") or "")[:39]
        updated = info.get("updated_at", "?")[:19]
        print(f"{jid:<38} {status:<12} {target:<40} {updated}")
    print(f"\nTotal: {result.get('count', len(jobs))} jobs")


def cmd_list_vulns(args):
    result = _api(args.server, "get", "/api/deepteam/vulnerabilities")
    cats = result.get("categories", {})
    print(f"\nDeepTeam Vulnerabilities ({result.get('count', 0)} total)\n")
    for cat, names in cats.items():
        print(f"  [{cat.upper()}]")
        for name in names:
            desc = result.get("vulnerabilities", {}).get(name, "")
            print(f"    {name:<40} {desc}")
        print()


def cmd_list_attacks(args):
    result = _api(args.server, "get", "/api/deepteam/attacks")
    print(f"\nDeepTeam Attack Methods ({result.get('count', 0)} total)\n")
    print("  [SINGLE-TURN]")
    for a in result.get("single_turn", []):
        print(f"    {a}")
    print("\n  [MULTI-TURN]")
    for a in result.get("multi_turn", []):
        print(f"    {a}")


def build_parser():
    p = argparse.ArgumentParser(description="DeepTeam red-team automation helper for Aegis-360")
    p.add_argument("--server", default=DEFAULT_SERVER, help=f"Aegis-360 server URL (default: {DEFAULT_SERVER})")

    sub = p.add_subparsers(dest="command", required=True)

    # Shared target args
    def add_target_args(sp):
        sp.add_argument("--endpoint", help="HTTP target endpoint URL")
        sp.add_argument("--model", help="OpenAI-compatible model name (e.g. gpt-4o-mini)")
        sp.add_argument("--api-key", help="API key for target model")
        sp.add_argument("--base-url", help="Custom OpenAI-compatible base URL (Ollama, LiteLLM)")
        sp.add_argument("--system-prompt", help="System prompt for the target LLM")
        sp.add_argument("--purpose", help="Target's intended purpose (improves attack quality)")
        sp.add_argument("--vulns", help="Comma-separated vulnerability names to test")
        sp.add_argument("--attacks", help="Comma-separated attack method names to use")
        sp.add_argument("--attacks-per-vuln", type=int, default=1, dest="attacks_per_vuln")
        sp.add_argument("--simulator-model", default="gpt-3.5-turbo-0125", dest="simulator_model")
        sp.add_argument("--evaluation-model", default="gpt-4o", dest="evaluation_model")
        sp.add_argument("--max-concurrent", type=int, default=5, dest="max_concurrent")

    # scan (blocking)
    s = sub.add_parser("scan", help="Run a synchronous DeepTeam scan")
    add_target_args(s)
    s.add_argument("--timeout", type=int, default=600, help="Max wait seconds (default: 600)")
    s.set_defaults(func=cmd_scan)

    # scan-async (background)
    sa = sub.add_parser("scan-async", help="Submit a background scan and optionally poll for results")
    add_target_args(sa)
    sa.add_argument("--poll", action="store_true", help="Poll until completion and print results")
    sa.set_defaults(func=cmd_scan_async)

    # status
    st = sub.add_parser("status", help="Check a job's status")
    st.add_argument("--job-id", required=True, dest="job_id")
    st.set_defaults(func=cmd_status)

    # report
    rp = sub.add_parser("report", help="Fetch completed job results")
    rp.add_argument("--job-id", required=True, dest="job_id")
    rp.set_defaults(func=cmd_report)

    # jobs
    jb = sub.add_parser("jobs", help="List all submitted jobs")
    jb.set_defaults(func=cmd_jobs)

    # list-vulnerabilities
    lv = sub.add_parser("list-vulnerabilities", help="List all vulnerability types")
    lv.set_defaults(func=cmd_list_vulns)

    # list-attacks
    la = sub.add_parser("list-attacks", help="List all attack methods")
    la.set_defaults(func=cmd_list_attacks)

    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
