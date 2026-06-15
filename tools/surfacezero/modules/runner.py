"""
Pipeline Runner - Orchestrates all SurfaceZero scan modules.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from modules.http_client import HTTPClient


class PipelineRunner:
    def __init__(self, config: dict, console: Console):
        self.config = config
        self.console = console
        self.client = HTTPClient(config)
        self.results = {
            "meta": {
                "target": config["target"],
                "timestamp": config["timestamp"],
                "engagement_id": config.get("engagement_id"),
                "tool": "SurfaceZero v2.1 | BinaryGalaxys Security",
            },
            "modules": {}
        }

    def _should_run(self, module: str) -> bool:
        modules = self.config.get("modules", "all")
        if modules == "all":
            return True
        if isinstance(modules, list) and "all" in modules:
            return True
        return module in modules

    async def _fetch_base(self) -> tuple:
        """Fetch the base target URL and return (html, resp)."""
        resp = await self.client.get(self.config["target"])
        if resp is None:
            self.console.print(f"[bold red][!] Cannot reach target: {self.config['target']}[/bold red]")
            return None, None
        return resp.text, resp

    def _print_module_result(self, module_name: str, result: dict):
        """Print a clean summary of module results."""
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Finding", style="yellow")
        table.add_column("Count", justify="right")
        table.add_column("Severity")

        if module_name == "secrets":
            sc = result.get("severity_summary", {})
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                count = sc.get(sev, 0)
                if count > 0:
                    color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[sev]
                    table.add_row("Secret Findings", str(count), f"[{color}]{sev}[/{color}]")

        elif module_name == "js_analysis":
            table.add_row("JS Files Discovered", str(result.get("js_files_found", 0)), "INFO")
            table.add_row("Endpoints Found", str(len(result.get("discovered_endpoints", []))), "MEDIUM")
            table.add_row("Source Maps Exposed", str(len(result.get("source_maps_exposed", []))), "[red]HIGH[/red]")
            table.add_row("Frameworks Detected", str(len(result.get("frameworks_detected", []))), "INFO")

        elif module_name == "graphql":
            ep = len(result.get("endpoints_found", []))
            table.add_row("Endpoints Found", str(ep), "[yellow]MED[/yellow]" if ep else "[green]NONE[/green]")
            table.add_row("Introspection Enabled", str(result.get("introspection_enabled")), "[red]HIGH[/red]" if result.get("introspection_enabled") else "[green]OK[/green]")
            table.add_row("Batch Queries Allowed", str(result.get("batch_queries_allowed")), "[yellow]MED[/yellow]" if result.get("batch_queries_allowed") else "[green]OK[/green]")
            table.add_row("Sensitive Operations", str(result.get("total_sensitive", 0)), "[red]HIGH[/red]")

        elif module_name == "headers_cors_tokens":
            table.add_row("CORS Issues", str(result.get("total_cors", 0)), "[red]HIGH[/red]" if result.get("total_cors") else "[green]OK[/green]")
            table.add_row("Missing Headers", str(result.get("total_header_issues", 0)), "[yellow]MED[/yellow]")
            table.add_row("Cookie Issues", str(result.get("total_cookie_issues", 0)), "[yellow]MED[/yellow]")
            table.add_row("Token Leaks", str(result.get("total_token_leaks", 0)), "[red]HIGH[/red]" if result.get("total_token_leaks") else "[green]OK[/green]")

        elif module_name == "pii":
            table.add_row("PII Findings", str(result.get("total", 0)), "[red]HIGH[/red]" if result.get("total") else "[green]OK[/green]")
            table.add_row("Critical PII", str(result.get("critical_count", 0)), "[bold red]CRITICAL[/bold red]" if result.get("critical_count") else "[green]OK[/green]")

        elif module_name == "paths":
            table.add_row("Accessible Paths", str(result.get("accessible_200", 0)), "[yellow]MED[/yellow]")
            table.add_row("Critical Finds", str(len(result.get("critical_finds", []))), "[red]HIGH[/red]" if result.get("critical_finds") else "[green]OK[/green]")
            table.add_row("OpenAPI Spec", "YES" if result.get("openapi_spec") else "NO", "[yellow]MED[/yellow]" if result.get("openapi_spec") else "INFO")

        elif module_name == "api_harvester":
            sev = result.get("severity_summary", {})
            table.add_row("Endpoints Probed", str(result.get("endpoints_probed", 0)), "INFO")
            table.add_row("Responding Endpoints", str(result.get("endpoints_responding", 0)), "[yellow]MED[/yellow]")
            table.add_row("Sensitive Data Endpoints", str(result.get("total_sensitive", 0)),
                          "[bold red]CRITICAL[/bold red]" if sev.get("CRITICAL", 0) else
                          "[red]HIGH[/red]" if result.get("total_sensitive") else "[green]NONE[/green]")
            table.add_row("Auth Bypass Hits", str(len(result.get("auth_bypass_hits", []))),
                          "[bold red]CRITICAL[/bold red]" if result.get("auth_bypass_hits") else "[green]NONE[/green]")
            sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}
            for sv in ["CRITICAL", "HIGH", "MEDIUM"]:
                cnt = sev.get(sv, 0)
                if cnt:
                    col = sev_colors[sv]
                    table.add_row(f"  ↳ {sv}", str(cnt), f"[{col}]{sv}[/{col}]")

        self.console.print(table)

    def _print_final_summary(self):
        """Print final risk summary across all modules."""
        self.console.print("\n")
        self.console.rule("[bold red]SCAN COMPLETE - RISK SUMMARY[/bold red]")

        total_critical = 0
        total_high = 0
        total_medium = 0

        m = self.results["modules"]

        if "secrets" in m:
            sc = m["secrets"].get("severity_summary", {})
            total_critical += sc.get("CRITICAL", 0)
            total_high += sc.get("HIGH", 0)
            total_medium += sc.get("MEDIUM", 0)

        if "headers_cors_tokens" in m:
            cors_count = m["headers_cors_tokens"].get("total_cors", 0)
            total_high += cors_count
            total_medium += m["headers_cors_tokens"].get("total_header_issues", 0)

        if "graphql" in m:
            if m["graphql"].get("introspection_enabled"):
                total_high += 1
            total_high += m["graphql"].get("total_sensitive", 0)

        if "pii" in m:
            total_critical += m["pii"].get("critical_count", 0)
            total_high += m["pii"].get("total", 0) - m["pii"].get("critical_count", 0)

        if "paths" in m:
            total_high += len(m["paths"].get("critical_finds", []))

        if "api_harvester" in m:
            ah_sev = m["api_harvester"].get("severity_summary", {})
            total_critical += ah_sev.get("CRITICAL", 0)
            total_high += ah_sev.get("HIGH", 0)
            total_medium += ah_sev.get("MEDIUM", 0)
            total_high += len(m["api_harvester"].get("auth_bypass_hits", []))

        risk_color = "green"
        risk_label = "LOW"
        if total_critical > 0:
            risk_color = "bold red"
            risk_label = "CRITICAL"
        elif total_high > 5:
            risk_color = "red"
            risk_label = "HIGH"
        elif total_high > 0 or total_medium > 3:
            risk_color = "yellow"
            risk_label = "MEDIUM"

        summary = Text()
        summary.append(f"\n  CRITICAL: {total_critical}  ", style="bold red")
        summary.append(f"HIGH: {total_high}  ", style="red")
        summary.append(f"MEDIUM: {total_medium}  ", style="yellow")
        summary.append(f"\n  Overall Risk: ", style="white")
        summary.append(risk_label, style=risk_color)

        self.console.print(Panel(summary, title="[bold]Risk Summary[/bold]", border_style=risk_color))

    async def run(self):
        """Main pipeline execution."""
        self.console.print(f"\n[bold cyan][*] Target:[/bold cyan] {self.config['target']}")
        self.console.print(f"[bold cyan][*] Engagement:[/bold cyan] {self.config.get('engagement_id', 'N/A')}")
        self.console.print(f"[bold cyan][*] Modules:[/bold cyan] {self.config.get('modules', 'all')}")
        if self.config.get("proxy"):
            self.console.print(f"[bold cyan][*] Proxy:[/bold cyan] {self.config['proxy']}")
        self.console.print()

        self.console.print("[*] Fetching target base page...")
        base_html, base_resp = await self._fetch_base()
        if base_html is None:
            return

        self.console.print(f"[green][+] Base page fetched ({len(base_html)} bytes, status {base_resp.status_code})[/green]")

        js_urls = []
        if self._should_run("js"):
            self.console.rule("[bold yellow]Module: JS Analysis[/bold yellow]")
            from modules.js_analyzer import JSAnalyzer
            js = JSAnalyzer(self.config)
            js_result = await js.run(base_html, self.config["target"])
            self.results["modules"]["js_analysis"] = js_result
            js_urls = js_result.get("js_urls", [])
            self._print_module_result("js_analysis", js_result)

        if self._should_run("secrets"):
            self.console.rule("[bold yellow]Module: Secrets Scanner[/bold yellow]")
            from modules.secrets_scanner import SecretsScanner
            ss = SecretsScanner(self.config)
            secrets_result = await ss.run(js_urls, base_html=base_html, base_url=self.config["target"])
            self.results["modules"]["secrets"] = secrets_result
            self._print_module_result("secrets", secrets_result)

        if self._should_run("graphql"):
            self.console.rule("[bold yellow]Module: GraphQL Enumeration[/bold yellow]")
            from modules.graphql_scanner import GraphQLScanner
            gql = GraphQLScanner(self.config)
            gql_result = await gql.run()
            self.results["modules"]["graphql"] = gql_result
            self._print_module_result("graphql", gql_result)

        if self._should_run("headers") or self._should_run("cors") or self._should_run("tokens"):
            self.console.rule("[bold yellow]Module: Headers / CORS / Cookies / Tokens[/bold yellow]")
            from modules.headers_cors import HeadersCORSScanner
            hc = HeadersCORSScanner(self.config)
            hc_result = await hc.run()
            self.results["modules"]["headers_cors_tokens"] = hc_result
            self._print_module_result("headers_cors_tokens", hc_result)

        if self._should_run("pii"):
            self.console.rule("[bold yellow]Module: PII Detection[/bold yellow]")
            from modules.pii_scanner import PIIScanner
            pii = PIIScanner(self.config)
            discovered = self.results.get("modules", {}).get("js_analysis", {}).get("discovered_endpoints", [])
            pii_result = await pii.run(base_html, self.config["target"], discovered)
            self.results["modules"]["pii"] = pii_result
            self._print_module_result("pii", pii_result)

        if self._should_run("paths") or self._should_run("api"):
            self.console.rule("[bold yellow]Module: Path & API Enumeration[/bold yellow]")
            from modules.path_scanner import PathScanner
            ps = PathScanner(self.config)
            path_result = await ps.run()
            self.results["modules"]["paths"] = path_result
            self._print_module_result("paths", path_result)

        if self._should_run("api_harvest") or self._should_run("api") or self.config.get("modules") == "all":
            self.console.rule("[bold yellow]Module: Unauthenticated API Data Harvester[/bold yellow]")
            from modules.api_harvester import APIHarvester
            harvester = APIHarvester(self.config)
            harvest_result = await harvester.run(scan_modules=self.results["modules"])
            self.results["modules"]["api_harvester"] = harvest_result
            self._print_module_result("api_harvester", harvest_result)

            if harvest_result.get("sensitive_endpoints"):
                from rich.table import Table as RTable
                self.console.print()
                self.console.print("[bold red]⚠  Unauthenticated API Data Retrieved:[/bold red]")
                dt = RTable(show_header=True, header_style="bold red", border_style="red")
                dt.add_column("URL", style="cyan", max_width=55)
                dt.add_column("Method", width=6)
                dt.add_column("Records")
                dt.add_column("Severity")
                dt.add_column("Sensitive Patterns")
                for ep in harvest_result["sensitive_endpoints"][:15]:
                    sev = ep["sensitivity"]["overall_severity"]
                    sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow"}
                    sc = sev_colors.get(sev, "white")
                    patterns = ", ".join(
                        p["type"] for p in ep["sensitivity"].get("sensitive_patterns", [])[:3]
                    )
                    # Fix: size_bytes is int, format properly
                    rec = ep["record_count"] if ep.get("record_count") is not None else f"{ep['size_bytes']}B"
                    dt.add_row(
                        ep["url"],
                        ep.get("method", "GET"),
                        str(rec),
                        f"[{sc}]{sev}[/{sc}]",
                        patterns,
                    )
                self.console.print(dt)

                output_dir2 = Path(self.config.get("output_dir", "output"))
                ts2 = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                target_safe2 = self.config["target"].replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
                harvest_file = output_dir2 / f"api_harvest_{target_safe2}_{ts2}.json"
                with open(harvest_file, "w") as hf:
                    json.dump({
                        "meta": self.results["meta"],
                        "summary": {
                            "total_sensitive": harvest_result["total_sensitive"],
                            "severity_summary": harvest_result["severity_summary"],
                            "auth_bypass_hits": len(harvest_result.get("auth_bypass_hits", [])),
                        },
                        "sensitive_endpoints": [
                            {
                                "url": ep["url"],
                                "method": ep.get("method", "GET"),
                                "status": ep["status_code"],
                                "record_count": ep.get("record_count"),
                                "sensitivity": ep["sensitivity"],
                                "retrieved_data": ep["data"],
                            }
                            for ep in harvest_result["sensitive_endpoints"]
                        ],
                        "auth_bypass_hits": harvest_result.get("auth_bypass_hits", []),
                        "all_responding_endpoints": [
                            {"url": ep["url"], "method": ep.get("method", "GET"),
                             "status": ep["status_code"], "size": ep["size_bytes"],
                             "sensitivity": ep["sensitivity"]["overall_severity"]}
                            for ep in harvest_result.get("full_harvest", [])
                        ],
                    }, hf, indent=2, default=str)
                self.console.print(f"[bold green][+] Harvest data saved: {harvest_file}[/bold green]")

        output_dir = Path(self.config.get("output_dir", "output"))
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target_safe = self.config["target"].replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        out_file = output_dir / f"preloginscan_{target_safe}_{ts}.json"

        with open(out_file, "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        self._print_final_summary()
        self.console.print(f"\n[bold green][+] Raw results saved: {out_file}[/bold green]")
        self.console.print(f"[dim]    Run: surfacezero report -i {out_file} -f html -o report.html[/dim]\n")
