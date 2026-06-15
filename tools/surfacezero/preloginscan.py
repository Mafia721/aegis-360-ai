#!/usr/bin/env python3
"""
SurfaceZero - Pre-Authentication Attack Surface Enumeration Tool
With AI-powered Threat Modeling, Kill Chain Analysis & MITRE ATT&CK Mapping
For authorized penetration testing engagements only.
Author: SJ / BinaryGalaxys Security
"""

import click
import sys
import json
import asyncio
import os
from pathlib import Path
from datetime import datetime, timezone
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
[bold red]
███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗
╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
███████╗███████╗██████╗  ██████╗
╚══███╔╝██╔════╝██╔══██╗██╔═══██╗
  ███╔╝ █████╗  ██████╔╝██║   ██║
 ███╔╝  ██╔══╝  ██╔══██╗██║   ██║
███████╗███████╗██║  ██║╚██████╔╝
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ [/bold red]
[bold yellow]Pre-Login Attack Surface Enumeration + AI Analyst | BinaryGalaxys Security[/bold yellow]
[dim]For Authorized Penetration Testing Only[/dim]
"""


@click.group()
@click.version_option(version="2.1.0")
def cli():
    """SurfaceZero - Pre-authentication attack surface enumeration + AI analyst.\n
    For authorized penetration testing engagements only.\n
    Run 'surfacezero COMMAND --help' for options."""
    console.print(BANNER)


@cli.command("scan")
@click.option("--target", "-t", required=True, help="Target URL (e.g. https://app.example.com)")
@click.option("--output", "-o", default="output", help="Output directory for reports")
@click.option("--format", "-f", "fmt", default="json", type=click.Choice(["json", "html", "md"]))
@click.option("--threads", default=10, help="Concurrent threads")
@click.option("--timeout", default=15, help="Request timeout in seconds")
@click.option("--proxy", default=None, help="Proxy URL (e.g. http://127.0.0.1:8080 for Burp)")
@click.option("--cookie", default=None, help="Cookie header value")
@click.option("--user-agent", default="SurfaceZero/2.1 (Security Assessment)")
@click.option("--modules", "-m", default="all",
              help="Modules: all, secrets,js,api,graphql,cors,headers,paths,pii")
@click.option("--aggressive", is_flag=True, default=False, help="Aggressive enumeration mode")
@click.option("--skip-ssl", is_flag=True, default=False, help="Skip SSL verification")
@click.option("--engagement-id", default=None, help="Engagement ID (e.g. PT37818)")
@click.option("--ai-analyze", is_flag=True, default=False, help="Run AI analysis after scan")
@click.option("--ai-model", default="claude", help="AI model to use (if --ai-analyze)")
@click.option("--ai-features", default="threat-model,kill-chain,mitre",
              help="AI features: threat-model,kill-chain,mitre,exploits,remediation")
@click.option("--api-key", default=None, help="AI API key")
@click.option("--verbose", "-v", is_flag=True, default=False)
def scan(target, output, fmt, threads, timeout, proxy, cookie, user_agent, modules,
         aggressive, skip_ssl, engagement_id, ai_analyze, ai_model, ai_features, api_key, verbose):
    """Run the full pre-login attack surface scan pipeline."""
    from modules.runner import PipelineRunner

    config = {
        "target": target,
        "output_dir": output,
        "report_format": fmt,
        "threads": threads,
        "timeout": timeout,
        "proxy": proxy,
        "cookie": cookie,
        "user_agent": user_agent,
        "modules": modules.split(",") if modules != "all" else "all",
        "aggressive": aggressive,
        "skip_ssl": skip_ssl,
        "engagement_id": engagement_id,
        "verbose": verbose,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    runner = PipelineRunner(config, console)
    asyncio.run(runner.run())

    if ai_analyze:
        import glob
        json_files = sorted(glob.glob(f"{output}/preloginscan_*.json"), key=os.path.getmtime, reverse=True)
        if json_files:
            latest = json_files[0]
            console.print(f"\n[bold cyan][*] Chaining AI analysis on: {latest}[/bold cyan]")
            _run_analyze(latest, ai_model, ai_features, None, api_key, "http://localhost:11434", engagement_id)


def _run_analyze(input_path, model, features, output, api_key, ollama_host, engagement_id=None):
    """Shared analyze logic used by both scan --ai-analyze and analyze command."""
    from modules.ai.analyst import AIAnalyst
    from modules.ai.ai_reporter import AIReportSection
    from modules.reporter import Reporter

    with open(input_path) as f:
        scan_data = json.load(f)

    if api_key:
        if "claude" in model:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        elif "deepseek" in model:
            os.environ["DEEPSEEK_API_KEY"] = api_key
        elif "gpt" in model:
            os.environ["OPENAI_API_KEY"] = api_key
        elif "gemini" in model:
            os.environ["GEMINI_API_KEY"] = api_key

    config = {
        "ollama_host": ollama_host,
        "engagement_id": engagement_id or scan_data.get("meta", {}).get("engagement_id", "N/A"),
    }

    feature_list = [f.strip() for f in features.split(",")]
    analyst = AIAnalyst(scan_data, model, config)
    ai_results = asyncio.run(analyst.run(feature_list))
    analyst.print_summary()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    target_safe = scan_data.get("meta", {}).get("target", "target") \
        .replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
    out_path = output or f"output/ai_report_{target_safe}_{ts}.html"

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)

    scan_data["meta"]["ai_model"] = model
    reporter = Reporter(scan_data, engagement_id=config["engagement_id"])

    base_html_path = out_path.replace(".html", "_base_tmp.html")
    reporter.generate_html(base_html_path)
    with open(base_html_path) as f:
        base_html = f.read()
    os.remove(base_html_path)

    ai_section_renderer = AIReportSection(ai_results, scan_data["meta"])
    ai_html = ai_section_renderer.render_all()
    final_html = base_html.replace(
        "</div>\n<div class=\"footer\"",
        ai_html + "\n</div>\n<div class=\"footer\""
    )

    with open(out_path, "w") as f:
        f.write(final_html)

    ai_json_path = out_path.replace(".html", "_ai_raw.json")
    with open(ai_json_path, "w") as f:
        json.dump({"meta": scan_data["meta"], "ai_analysis": ai_results}, f, indent=2, default=str)

    console.print(f"\n[bold green][+] AI report: {out_path}[/bold green]")
    console.print(f"[dim]    Raw AI JSON: {ai_json_path}[/dim]\n")
    return out_path


@cli.command("analyze")
@click.option("--input", "-i", "input_path", required=True, help="Path to raw JSON scan output")
@click.option("--model", "-m", default="claude", show_default=True,
              help="AI model: claude, claude-haiku, deepseek, deepseek-chat, gpt4, gemini, ollama:llama3")
@click.option("--features", "-f", default="threat-model,kill-chain,mitre",
              help="Features: threat-model,kill-chain,mitre,exploits,remediation (comma-separated)")
@click.option("--output", "-o", default=None, help="Output HTML report path")
@click.option("--api-key", default=None, help="AI API key (or set env var)")
@click.option("--ollama-host", default="http://localhost:11434", help="Ollama host URL")
@click.option("--engagement-id", default=None, help="Engagement ID")
def analyze(input_path, model, features, output, api_key, ollama_host, engagement_id):
    """Run AI threat modeling + kill chain analysis on existing scan results."""
    _run_analyze(input_path, model, features, output, api_key, ollama_host, engagement_id)


@cli.command("chat")
@click.option("--input", "-i", "input_path", required=True, help="Path to raw JSON scan output")
@click.option("--model", "-m", default="claude", show_default=True,
              help="AI model: claude, deepseek, gpt4, gemini, ollama:llama3")
@click.option("--api-key", default=None, help="AI API key")
@click.option("--ollama-host", default="http://localhost:11434", help="Ollama host URL")
def chat(input_path, model, api_key, ollama_host):
    """Interactive AI security analyst chat with scan context pre-loaded."""
    from modules.ai.analyst import ChatSession

    with open(input_path) as f:
        scan_data = json.load(f)

    if api_key:
        if "claude" in model:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        elif "deepseek" in model:
            os.environ["DEEPSEEK_API_KEY"] = api_key
        elif "gpt" in model:
            os.environ["OPENAI_API_KEY"] = api_key
        elif "gemini" in model:
            os.environ["GEMINI_API_KEY"] = api_key

    config = {"ollama_host": ollama_host}
    session = ChatSession(scan_data, model, config)
    asyncio.run(session.run())


@cli.command("models")
def list_models():
    """List all supported AI models and required API keys."""
    from rich.table import Table
    table = Table(title="Supported AI Models", header_style="bold cyan")
    table.add_column("Alias", style="bold yellow")
    table.add_column("Provider")
    table.add_column("Model ID", style="cyan")
    table.add_column("Env Var Required")
    table.add_column("Cost")
    table.add_column("Best For")

    rows = [
        ("claude",        "Anthropic",  "claude-sonnet-4-6",        "ANTHROPIC_API_KEY", "Paid",    "Best reasoning + reports"),
        ("claude-haiku",  "Anthropic",  "claude-haiku-4-5-20251001","ANTHROPIC_API_KEY", "Cheap",   "Fast, low cost"),
        ("claude-opus",   "Anthropic",  "claude-opus-4-8",          "ANTHROPIC_API_KEY", "High",    "Complex analysis"),
        ("deepseek",      "DeepSeek",   "deepseek-reasoner",        "DEEPSEEK_API_KEY",  "Cheap",   "Kill chains, reasoning"),
        ("deepseek-chat", "DeepSeek",   "deepseek-chat",            "DEEPSEEK_API_KEY",  "Cheapest","Fast summarization"),
        ("gpt4",          "OpenAI",     "gpt-4o",                   "OPENAI_API_KEY",    "Paid",    "Alternative to Claude"),
        ("gemini",        "Google",     "gemini-1.5-flash",         "GEMINI_API_KEY",    "Free tier","Quick recon"),
        ("gemini-pro",    "Google",     "gemini-1.5-pro",           "GEMINI_API_KEY",    "Paid",    "Deeper analysis"),
        ("ollama:llama3", "Local/Ollama","llama3",                  "None (self-hosted)","Free",    "Air-gapped / offline"),
        ("ollama:mistral","Local/Ollama","mistral",                 "None (self-hosted)","Free",    "Fast local inference"),
        ("ollama:deepseek-r1:7b","Local","deepseek-r1:7b",         "None (self-hosted)","Free",    "Local reasoning"),
    ]
    for r in rows:
        table.add_row(*r)
    console.print(table)

    console.print("\n[dim]Usage examples:[/dim]")
    console.print("  [cyan]python3 preloginscan.py analyze -i scan.json --model claude[/cyan]")
    console.print("  [cyan]python3 preloginscan.py analyze -i scan.json --model deepseek --api-key $DEEPSEEK_API_KEY[/cyan]")
    console.print("  [cyan]python3 preloginscan.py analyze -i scan.json --model ollama:llama3[/cyan]  [dim](no key needed)[/dim]")
    console.print("  [cyan]python3 preloginscan.py chat -i scan.json --model deepseek[/cyan]\n")


@cli.command("modules")
def list_modules():
    """List all available scan modules."""
    from rich.table import Table
    table = Table(title="Available Scan Modules", show_header=True, header_style="bold cyan")
    table.add_column("Module", style="bold yellow")
    table.add_column("Description")
    table.add_column("Risk Level", justify="center")
    table.add_column("Tags")

    module_list = [
        ("secrets",      "Scan JS/HTML/CSS for hardcoded API keys, tokens, credentials", "[red]HIGH[/red]",   "OSCP, BugBounty"),
        ("js",           "Enumerate and analyze JavaScript files for endpoints/secrets",  "[red]HIGH[/red]",   "Recon, AppSec"),
        ("api",          "Discover hidden REST API endpoints pre-auth",                   "[yellow]MED[/yellow]", "REST, AppSec"),
        ("graphql",      "Introspect GraphQL schemas, mutations, queries",                "[red]HIGH[/red]",   "GraphQL, IDOR"),
        ("cors",         "Test CORS misconfiguration on public endpoints",                "[yellow]MED[/yellow]", "CORS, AppSec"),
        ("headers",      "Audit security headers on pre-login responses",                 "[green]LOW[/green]","Hardening"),
        ("paths",        "Directory/path brute-force (pre-auth resources)",               "[yellow]MED[/yellow]", "Recon"),
        ("pii",          "Detect PII leakage in public responses",                        "[red]HIGH[/red]",   "Privacy, GDPR"),
        ("cookies",      "Analyze cookie attributes (HttpOnly, Secure, SameSite)",        "[yellow]MED[/yellow]", "Session"),
        ("tokens",       "Detect JWT/OAuth token exposure in pre-auth flows",             "[red]HIGH[/red]",   "AuthN"),
        ("source-maps",  "Detect exposed .map files leaking source code",                 "[red]HIGH[/red]",   "Leakage"),
        ("openapi",      "Find exposed Swagger/OpenAPI specs",                            "[yellow]MED[/yellow]", "API, Recon"),
    ]
    for mod in module_list:
        table.add_row(*mod)
    console.print(table)


@cli.command("report")
@click.option("--input", "-i", "input_path", required=True, help="Path to raw JSON scan output")
@click.option("--format", "-f", "fmt", default="html", type=click.Choice(["html", "md"]))
@click.option("--output", "-o", default="report.html", help="Output file path")
@click.option("--engagement-id", default=None, help="Engagement ID for header")
def report(input_path, fmt, output, engagement_id):
    """Convert raw JSON scan results into a formatted pentest report."""
    from modules.reporter import Reporter
    with open(input_path) as f:
        data = json.load(f)
    reporter = Reporter(data, engagement_id=engagement_id)
    reporter.generate(fmt, output)
    console.print(f"[bold green][+] Report generated: {output}[/bold green]")


if __name__ == "__main__":
    cli()
