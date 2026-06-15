"""
AI Analyst - Orchestrates multi-feature AI analysis of scan results.
Handles: threat-model, kill-chain, mitre, exploits, remediation, chat
"""

import json
import asyncio
import re
from typing import List, Dict, Optional
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.spinner import Spinner
from rich.live import Live
from rich.text import Text
from rich.table import Table
from rich.markdown import Markdown

from modules.ai.model_router import ModelRouter
from modules.ai.prompt_engine import (
    SYSTEM_PROMPT, extract_summary, build_prompt, PROMPT_MAP
)

console = Console()


class AIAnalyst:
    def __init__(self, scan_data: dict, model_str: str, config: dict = None):
        self.scan_data = scan_data
        self.model_str = model_str
        self.config = config or {}
        self.router = ModelRouter(model_str, config)
        self.summary = extract_summary(scan_data)
        self.results = {}

    def _parse_json_response(self, raw: str) -> Optional[dict]:
        """Robustly parse JSON from model response."""
        # Strip markdown code fences
        clean = re.sub(r"```json\s*|```\s*", "", raw).strip()

        # Try direct parse
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            pass

        # Find first { ... } block
        try:
            start = clean.index("{")
            end = clean.rindex("}") + 1
            return json.loads(clean[start:end])
        except (ValueError, json.JSONDecodeError):
            pass

        return None

    async def _run_feature(self, feature: str) -> Dict:
        """Run a single AI analysis feature."""
        user_prompt = build_prompt(feature, self.summary)

        with Live(
            Panel(f"[bold yellow]⚙ Analyzing:[/bold yellow] [cyan]{feature}[/cyan]  [dim]model: {self.router.describe()}[/dim]"),
            refresh_per_second=4,
            console=console
        ):
            try:
                raw = await self.router.complete(
                    system=SYSTEM_PROMPT,
                    user=user_prompt,
                    max_tokens=4096
                )
            except Exception as e:
                console.print(f"[red][!] {feature} failed: {e}[/red]")
                return {"feature": feature, "error": str(e)}

        parsed = self._parse_json_response(raw)
        if parsed:
            console.print(f"[green][✓] {feature} complete[/green]")
            return {"feature": feature, "data": parsed, "raw": raw}
        else:
            console.print(f"[yellow][~] {feature} returned non-JSON response[/yellow]")
            return {"feature": feature, "data": None, "raw": raw}

    async def run(self, features: List[str]) -> Dict:
        """Run all requested features sequentially (to avoid rate limits)."""
        console.print(f"\n[bold cyan][*] AI Model:[/bold cyan] {self.router.describe()}")
        console.print(f"[bold cyan][*] Features:[/bold cyan] {', '.join(features)}")
        console.print(f"[bold cyan][*] Target:[/bold cyan] {self.summary['target']}\n")

        for feature in features:
            result = await self._run_feature(feature)
            self.results[feature] = result

        return self.results

    def _print_kill_chain(self, data: dict):
        kc = data.get("kill_chain", {})
        console.print(Panel(
            f"[bold]{kc.get('overview', '')}[/bold]\n\n"
            f"[dim]Estimated time to compromise: {kc.get('estimated_time_to_compromise', 'N/A')}[/dim]\n"
            f"[dim]Skill required: {kc.get('attacker_skill_required', 'N/A')}[/dim]",
            title="[bold red]⚔ Attack Kill Chain[/bold red]",
            border_style="red"
        ))

        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("#", style="dim", width=3)
        table.add_column("Phase", style="yellow")
        table.add_column("Action")
        table.add_column("MITRE ID", style="cyan")
        table.add_column("Evidence", style="dim")

        for phase in kc.get("phases", []):
            table.add_row(
                str(phase.get("phase_number", "")),
                phase.get("phase_name", ""),
                phase.get("attacker_action", ""),
                phase.get("mitre_technique_id", ""),
                phase.get("evidence", "")[:60] + "..." if len(phase.get("evidence", "")) > 60 else phase.get("evidence", ""),
            )
        console.print(table)

    def _print_threat_model(self, data: dict):
        tm = data.get("threat_model", {})
        console.print(Panel(
            tm.get("executive_summary", ""),
            title="[bold red]🔍 Threat Model (STRIDE)[/bold red]",
            border_style="red"
        ))

        stride = tm.get("stride_analysis", {})
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("STRIDE Category", style="yellow")
        table.add_column("Risk", justify="center")
        table.add_column("Description")

        risk_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        for cat, details in stride.items():
            if isinstance(details, dict):
                risk = details.get("risk_level", "LOW")
                color = risk_colors.get(risk, "white")
                table.add_row(
                    cat.replace("_", " "),
                    f"[{color}]{risk}[/{color}]",
                    details.get("description", "")[:100]
                )
        console.print(table)

    def _print_mitre(self, data: dict):
        mm = data.get("mitre_mapping", {})
        console.print(Panel(
            f"Techniques mapped: [bold]{mm.get('total_techniques', 0)}[/bold]  |  "
            f"Tactics covered: [bold]{len(mm.get('tactics_covered', []))}[/bold]",
            title="[bold red]🎯 MITRE ATT&CK Mapping[/bold red]",
            border_style="red"
        ))

        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Finding", style="yellow")
        table.add_column("Technique ID", style="cyan")
        table.add_column("Technique Name")
        table.add_column("Tactic")
        table.add_column("Sev", justify="center")

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
        for m in mm.get("mappings", [])[:20]:
            sev = m.get("finding_severity", "LOW")
            color = sev_colors.get(sev, "white")
            table.add_row(
                m.get("finding_type", "")[:40],
                m.get("technique_id", ""),
                m.get("technique_name", "")[:35],
                m.get("tactic", ""),
                f"[{color}]{sev[:4]}[/{color}]",
            )
        console.print(table)

    def print_summary(self):
        """Print rich CLI summary of all completed analysis."""
        console.rule("[bold red]AI ANALYSIS RESULTS[/bold red]")

        for feature, result in self.results.items():
            if result.get("error"):
                console.print(f"[red][!] {feature}: {result['error']}[/red]")
                continue

            data = result.get("data")
            if not data:
                console.print(f"[yellow][~] {feature}: Raw response only (non-JSON)[/yellow]")
                console.print(result.get("raw", "")[:500])
                continue

            if feature == "kill-chain":
                self._print_kill_chain(data)
            elif feature == "threat-model":
                self._print_threat_model(data)
            elif feature == "mitre":
                self._print_mitre(data)
            else:
                console.print(Panel(
                    f"[green]✓ {feature} analysis complete — saved to output[/green]",
                    border_style="green"
                ))


# ─── Interactive Chat Session ────────────────────────────────────────────────

class ChatSession:
    """Interactive AI chat with full scan context pre-loaded."""

    CHAT_SYSTEM = """You are a senior penetration tester with deep expertise in web application security and red team operations. You have been given the complete results of a pre-authentication attack surface scan. Answer questions about the findings, suggest follow-up tests, explain vulnerabilities, and help build exploitation strategies.

Be concise and technical. Reference specific findings from the scan data when answering. Format code/commands in backticks."""

    def __init__(self, scan_data: dict, model_str: str, config: dict = None):
        self.scan_data = scan_data
        self.router = ModelRouter(model_str, config or {})
        self.summary = extract_summary(scan_data)
        self.history = []

        # Pre-load scan context into system prompt
        self.system = (
            self.CHAT_SYSTEM +
            f"\n\n=== SCAN RESULTS CONTEXT ===\n"
            f"{json.dumps(self.summary, indent=2)}\n"
            f"=== END CONTEXT ==="
        )

    async def _send(self, user_message: str) -> str:
        self.history.append({"role": "user", "content": user_message})

        # Build conversation context
        conversation = "\n\n".join([
            f"{'User' if m['role'] == 'user' else 'Assistant'}: {m['content']}"
            for m in self.history
        ])

        try:
            response = await self.router.complete(
                system=self.system,
                user=conversation,
                max_tokens=2048
            )
        except Exception as e:
            response = f"[Error: {e}]"

        self.history.append({"role": "assistant", "content": response})
        return response

    async def run(self):
        """Start interactive chat loop."""
        target = self.summary.get("target", "Unknown")

        console.print(Panel(
            f"[bold green]AI Security Analyst — Interactive Mode[/bold green]\n"
            f"[dim]Model: {self.router.describe()} | Target: {target}[/dim]\n\n"
            f"Scan context loaded. Ask anything about the findings.\n"
            f"[dim]Commands: 'exit' to quit, 'clear' to reset, 'summary' for finding overview[/dim]",
            border_style="green"
        ))

        suggested = [
            "What's the most critical finding I should exploit first?",
            "Build me an attack kill chain from these findings",
            "What's the fastest path to credential access?",
            "Which GraphQL mutations can I abuse without auth?",
            "Write me a CORS PoC for Burp Suite",
        ]
        console.print("[dim]Suggested questions:[/dim]")
        for i, q in enumerate(suggested, 1):
            console.print(f"  [dim]{i}.[/dim] {q}")
        console.print()

        while True:
            try:
                user_input = console.input("[bold cyan]You:[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Session ended.[/dim]")
                break

            if not user_input:
                continue
            if user_input.lower() in ["exit", "quit", "q"]:
                console.print("[dim]Session ended.[/dim]")
                break
            if user_input.lower() == "clear":
                self.history = []
                console.print("[dim]History cleared.[/dim]")
                continue
            if user_input.lower() == "summary":
                console.print_json(json.dumps(self.summary, indent=2))
                continue

            with Live(
                Text("⚙ Thinking...", style="dim"),
                refresh_per_second=4,
                console=console
            ):
                response = await self._send(user_input)

            console.print(f"\n[bold red]AI Analyst:[/bold red]")
            try:
                console.print(Markdown(response))
            except Exception:
                console.print(response)
            console.print()
