"""
Reporter - Generates pentest reports from raw scan JSON.
Supports: HTML, Markdown
"""

import json
from datetime import datetime
from typing import Dict, Optional


class Reporter:
    def __init__(self, data: dict, engagement_id: Optional[str] = None):
        self.data = data
        self.engagement_id = engagement_id or data.get("meta", {}).get("engagement_id", "N/A")
        self.target = data.get("meta", {}).get("target", "Unknown")
        self.timestamp = data.get("meta", {}).get("timestamp", datetime.utcnow().isoformat())
        self.modules = data.get("modules", {})

    def _severity_badge(self, sev: str) -> str:
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#65a30d",
            "INFO": "#0284c7",
        }
        color = colors.get(sev.upper(), "#6b7280")
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.78em;font-weight:700">{sev}</span>'

    def _count_findings(self) -> Dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        m = self.modules
        if "secrets" in m:
            sc = m["secrets"].get("severity_summary", {})
            for k in counts:
                counts[k] += sc.get(k, 0)

        if "graphql" in m:
            if m["graphql"].get("introspection_enabled"):
                counts["HIGH"] += 1
            counts["HIGH"] += m["graphql"].get("total_sensitive", 0)
            if m["graphql"].get("batch_queries_allowed"):
                counts["MEDIUM"] += 1

        if "headers_cors_tokens" in m:
            counts["HIGH"] += m["headers_cors_tokens"].get("total_cors", 0)
            counts["MEDIUM"] += m["headers_cors_tokens"].get("total_header_issues", 0)
            counts["MEDIUM"] += m["headers_cors_tokens"].get("total_cookie_issues", 0)
            counts["HIGH"] += m["headers_cors_tokens"].get("total_token_leaks", 0)

        if "pii" in m:
            counts["CRITICAL"] += m["pii"].get("critical_count", 0)
            counts["HIGH"] += m["pii"].get("total", 0) - m["pii"].get("critical_count", 0)

        if "paths" in m:
            counts["HIGH"] += len(m["paths"].get("critical_finds", []))

        return counts

    def generate_html(self, output_path: str):
        counts = self._count_findings()
        total = sum(counts.values())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PreLoginScan Report - {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{ background: linear-gradient(135deg, #1e1b4b 0%, #0f172a 100%); padding: 40px; border-bottom: 2px solid #dc2626; }}
  .header h1 {{ font-size: 2rem; color: #f8fafc; margin-bottom: 8px; }}
  .header h1 span {{ color: #dc2626; }}
  .meta {{ display: flex; gap: 24px; flex-wrap: wrap; margin-top: 16px; }}
  .meta-item {{ font-size: 0.85em; color: #94a3b8; }}
  .meta-item strong {{ color: #cbd5e1; }}
  .content {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  .risk-bar {{ display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }}
  .risk-card {{ flex: 1; min-width: 120px; background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; border-top: 3px solid; }}
  .risk-critical {{ border-color: #dc2626; }}
  .risk-high {{ border-color: #ea580c; }}
  .risk-medium {{ border-color: #d97706; }}
  .risk-low {{ border-color: #65a30d; }}
  .risk-num {{ font-size: 2.5rem; font-weight: 800; }}
  .risk-label {{ font-size: 0.75em; color: #94a3b8; margin-top: 4px; letter-spacing: 0.1em; }}
  .section {{ background: #1e293b; border-radius: 8px; margin: 24px 0; overflow: hidden; }}
  .section-header {{ padding: 14px 20px; background: #0f172a; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; cursor: pointer; }}
  .section-header h2 {{ font-size: 1rem; font-weight: 600; color: #f1f5f9; }}
  .section-body {{ padding: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875em; }}
  th {{ text-align: left; padding: 10px 12px; background: #0f172a; color: #94a3b8; font-size: 0.75em; letter-spacing: 0.1em; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #0f172a; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 700; }}
  .badge-crit {{ background: #dc2626; color: #fff; }}
  .badge-high {{ background: #ea580c; color: #fff; }}
  .badge-med {{ background: #d97706; color: #fff; }}
  .badge-low {{ background: #65a30d; color: #fff; }}
  .badge-info {{ background: #0284c7; color: #fff; }}
  code {{ background: #0f172a; padding: 2px 6px; border-radius: 3px; font-family: monospace; font-size: 0.85em; color: #7dd3fc; word-break: break-all; }}
  .empty {{ color: #475569; font-style: italic; padding: 12px; }}
  .footer {{ text-align: center; padding: 24px; color: #475569; font-size: 0.8em; border-top: 1px solid #1e293b; margin-top: 48px; }}
  .tag {{ background: #1e3a5f; color: #7dd3fc; padding: 1px 6px; border-radius: 3px; font-size: 0.75em; }}
</style>
</head>
<body>
<div class="header">
  <h1>Pre<span>Login</span>Scan Report</h1>
  <p style="color:#94a3b8;margin-top:4px">Pre-Authentication Attack Surface Enumeration</p>
  <div class="meta">
    <div class="meta-item"><strong>Target:</strong> {self.target}</div>
    <div class="meta-item"><strong>Engagement:</strong> {self.engagement_id}</div>
    <div class="meta-item"><strong>Date:</strong> {self.timestamp[:19].replace("T", " ")} UTC</div>
    <div class="meta-item"><strong>Tool:</strong> PreLoginScan v1.0 | BinaryGalaxys Security</div>
    <div class="meta-item"><strong>Total Findings:</strong> {total}</div>
  </div>
</div>

<div class="content">
  <div class="risk-bar">
    <div class="risk-card risk-critical"><div class="risk-num" style="color:#dc2626">{counts['CRITICAL']}</div><div class="risk-label">CRITICAL</div></div>
    <div class="risk-card risk-high"><div class="risk-num" style="color:#ea580c">{counts['HIGH']}</div><div class="risk-label">HIGH</div></div>
    <div class="risk-card risk-medium"><div class="risk-num" style="color:#d97706">{counts['MEDIUM']}</div><div class="risk-label">MEDIUM</div></div>
    <div class="risk-card risk-low"><div class="risk-num" style="color:#65a30d">{counts['LOW']}</div><div class="risk-label">LOW</div></div>
  </div>
"""
        # Secrets section
        if "secrets" in self.modules:
            sec = self.modules["secrets"]
            findings = sec.get("findings", [])
            html += f"""
  <div class="section">
    <div class="section-header"><span>🔑</span><h2>Hardcoded Secrets ({len(findings)} findings)</h2></div>
    <div class="section-body">
"""
            if findings:
                html += """<table><tr><th>Type</th><th>Severity</th><th>Match (Truncated)</th><th>Source</th></tr>"""
                for f in findings[:50]:
                    b = self._badge(f['severity'])
                    html += f"<tr><td>{f['type']}</td><td>{b}</td><td><code>{self._escape(f['match'])}</code></td><td><code>{self._escape(f['source'])}</code></td></tr>"
                html += "</table>"
            else:
                html += '<p class="empty">No secrets found.</p>'
            html += "</div></div>"

        # GraphQL section
        if "graphql" in self.modules:
            gql = self.modules["graphql"]
            endpoints = gql.get("endpoints_found", [])
            sensitive = gql.get("sensitive_operations", [])
            html += f"""
  <div class="section">
    <div class="section-header"><span>🕸️</span><h2>GraphQL ({len(endpoints)} endpoints)</h2></div>
    <div class="section-body">
    <p style="margin-bottom:12px">
      Introspection Enabled: {self._bool_badge(gql.get('introspection_enabled'))} &nbsp;
      Batch Queries: {self._bool_badge(gql.get('batch_queries_allowed'))} &nbsp;
      Field Suggestions: {self._bool_badge(gql.get('field_suggestions_enabled'))}
    </p>
"""
            if sensitive:
                html += """<table><tr><th>Operation</th><th>Parent Type</th><th>Risk</th><th>Reason</th></tr>"""
                for op in sensitive[:30]:
                    html += f"<tr><td><code>{op['operation']}</code></td><td>{op['parent_type']}</td><td>{self._badge(op['risk'])}</td><td>{op['reason']}</td></tr>"
                html += "</table>"
            elif endpoints:
                html += '<p class="empty">Endpoints found but no sensitive operations detected.</p>'
            else:
                html += '<p class="empty">No GraphQL endpoints detected.</p>'
            html += "</div></div>"

        # Headers / CORS
        if "headers_cors_tokens" in self.modules:
            hct = self.modules["headers_cors_tokens"]
            cors = hct.get("cors_findings", [])
            headers = hct.get("header_audit", [])
            html += f"""
  <div class="section">
    <div class="section-header"><span>🛡️</span><h2>Headers / CORS / Tokens</h2></div>
    <div class="section-body">
"""
            if cors:
                html += "<h3 style='color:#f87171;margin-bottom:8px'>CORS Misconfigurations</h3>"
                html += """<table><tr><th>URL</th><th>Test Origin</th><th>Severity</th><th>Details</th></tr>"""
                for c in cors:
                    html += f"<tr><td><code>{self._escape(c['url'])}</code></td><td><code>{self._escape(c['test_origin'])}</code></td><td>{self._badge(c['severity'])}</td><td>{c['description']}</td></tr>"
                html += "</table>"

            missing_headers = []
            for ha in headers:
                missing_headers.extend(ha.get("missing_or_weak_headers", []))
            if missing_headers:
                html += "<h3 style='color:#fbbf24;margin:16px 0 8px'>Missing/Weak Security Headers</h3>"
                html += """<table><tr><th>Header</th><th>Status</th><th>Severity</th><th>Description</th></tr>"""
                for h in missing_headers[:20]:
                    html += f"<tr><td><code>{h['header']}</code></td><td>{h['status']}</td><td>{self._badge(h['severity'])}</td><td>{h['description']}</td></tr>"
                html += "</table>"

            if not cors and not missing_headers:
                html += '<p class="empty">No significant header or CORS issues found.</p>'
            html += "</div></div>"

        # PII
        if "pii" in self.modules:
            pii = self.modules["pii"]
            findings = pii.get("findings", [])
            html += f"""
  <div class="section">
    <div class="section-header"><span>👤</span><h2>PII Exposure ({len(findings)} findings)</h2></div>
    <div class="section-body">
"""
            if findings:
                html += """<table><tr><th>PII Type</th><th>Severity</th><th>Count</th><th>Source URL</th><th>Samples (Redacted)</th></tr>"""
                for f in findings[:30]:
                    samples = ", ".join(f.get("samples_redacted", [])[:3])
                    html += f"<tr><td>{f['type']}</td><td>{self._badge(f['severity'])}</td><td>{f['count']}</td><td><code>{self._escape(f['source'])}</code></td><td><code>{self._escape(samples)}</code></td></tr>"
                html += "</table>"
            else:
                html += '<p class="empty">No PII detected in pre-auth responses.</p>'
            html += "</div></div>"

        # Paths
        if "paths" in self.modules:
            paths = self.modules["paths"]
            critical_finds = paths.get("critical_finds", [])
            all_accessible = paths.get("all_accessible", [])
            openapi = paths.get("openapi_spec")
            html += f"""
  <div class="section">
    <div class="section-header"><span>📁</span><h2>Path Enumeration ({paths.get('accessible_200', 0)} accessible)</h2></div>
    <div class="section-body">
"""
            if openapi:
                html += f"""<div style="background:#0f172a;border-left:3px solid #d97706;padding:12px 16px;margin-bottom:16px;border-radius:0 4px 4px 0">
                  <strong>⚠️ OpenAPI Spec Exposed:</strong> <code>{openapi['spec_url']}</code><br>
                  <small style="color:#94a3b8">{openapi['title']} v{openapi['version']} — {openapi['endpoint_count']} endpoints documented</small>
                </div>"""

            if critical_finds:
                html += """<table><tr><th>Path</th><th>Status</th><th>Size</th><th>Severity</th><th>Content-Type</th></tr>"""
                for f in critical_finds:
                    html += f"<tr><td><code>{self._escape(f['path'])}</code></td><td>{f['status']}</td><td>{f['size']}</td><td>{self._badge(f['severity'])}</td><td>{f.get('content_type','')[:50]}</td></tr>"
                html += "</table>"
            elif all_accessible:
                html += f'<p class="empty">{len(all_accessible)} accessible paths found but none flagged as critical.</p>'
            else:
                html += '<p class="empty">No sensitive accessible paths found.</p>'
            html += "</div></div>"


        # API Harvester section
        if "api_harvester" in self.modules:
            ah = self.modules["api_harvester"]
            sensitive = ah.get("sensitive_endpoints", [])
            bypass_hits = ah.get("auth_bypass_hits", [])
            sev_s = ah.get("severity_summary", {})

            html += f"""
  <div class="section">
    <div class="section-header"><span>&#127760;</span>
      <h2>Unauthenticated API Data Harvester ({ah.get('total_sensitive', 0)} sensitive endpoints)</h2>
    </div>
    <div class="section-body">
      <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
        <div style="background:#0f172a;border-top:3px solid #dc2626;border-radius:6px;padding:12px 20px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#dc2626">{sev_s.get('CRITICAL',0)}</div><div style="font-size:0.75em;color:#94a3b8">CRITICAL</div></div>
        <div style="background:#0f172a;border-top:3px solid #ea580c;border-radius:6px;padding:12px 20px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#ea580c">{sev_s.get('HIGH',0)}</div><div style="font-size:0.75em;color:#94a3b8">HIGH</div></div>
        <div style="background:#0f172a;border-top:3px solid #d97706;border-radius:6px;padding:12px 20px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#d97706">{sev_s.get('MEDIUM',0)}</div><div style="font-size:0.75em;color:#94a3b8">MEDIUM</div></div>
        <div style="background:#0f172a;border-top:3px solid #7c3aed;border-radius:6px;padding:12px 20px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#7c3aed">{len(bypass_hits)}</div><div style="font-size:0.75em;color:#94a3b8">AUTH BYPASS</div></div>
        <div style="background:#0f172a;border-top:3px solid #0284c7;border-radius:6px;padding:12px 20px;text-align:center"><div style="font-size:2rem;font-weight:800;color:#0284c7">{ah.get('endpoints_responding',0)}</div><div style="font-size:0.75em;color:#94a3b8">RESPONDING</div></div>
      </div>"""

            if bypass_hits:
                html += "<div style='background:#3b0764;border:1px solid #7c3aed;border-radius:6px;padding:14px;margin-bottom:16px'><h3 style='color:#c4b5fd;margin:0 0 8px'>&#128275; Authentication Bypass Hits</h3>"
                for bp in bypass_hits:
                    bhdrs = self._escape(str(bp.get('bypass_headers_used', {})))
                    html += f"<div style='background:#0f172a;padding:10px;border-radius:4px;margin:6px 0'><code style='color:#7dd3fc'>{self._escape(bp['url'])}</code><span style='color:#94a3b8;font-size:0.8em;margin-left:10px'>via: {bhdrs}</span></div>"
                html += "</div>"

            for ep in sensitive[:30]:
                import json as _json
                sev = ep.get("sensitivity", {}).get("overall_severity", "INFO")
                sev_clr = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d"}.get(sev, "#6b7280")
                patterns = ep.get("sensitivity", {}).get("sensitive_patterns", [])
                pat_html = "".join(
                    f"<span style='background:#1e293b;color:#94a3b8;padding:1px 8px;border-radius:12px;font-size:0.75em;margin:2px'>{p['type']} ({p['count']})</span>"
                    for p in patterns[:5]
                )
                exposure = self._escape(ep.get("sensitivity", {}).get("exposure_estimate", ""))
                try:
                    data_preview = _json.dumps(ep.get("data", {}), indent=2, default=str)
                    if len(data_preview) > 3000:
                        data_preview = data_preview[:3000] + "\n... [truncated]"
                except Exception:
                    data_preview = str(ep.get("data", ""))[:3000]
                data_escaped = self._escape(data_preview)
                rec = ep.get("record_count")
                rec_html = f"<span style='color:#64748b;font-size:0.8em'>Records: {rec}</span>" if rec is not None else ""
                bypass_badge = "<span style='background:#3b0764;color:#c4b5fd;padding:1px 8px;border-radius:12px;font-size:0.75em'>AUTH BYPASS</span>" if ep.get('auth_bypass') else ""

                html += f"""
      <div style="background:#0f172a;border:1px solid #334155;border-left:4px solid {sev_clr};border-radius:6px;padding:14px;margin:10px 0">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap">
          <span style="background:{sev_clr};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:700">{sev}</span>
          <code style="color:#7dd3fc;font-size:0.9em">{ep.get('method','GET')} {self._escape(ep['url'])}</code>
          <span style="color:#64748b;font-size:0.8em">HTTP {ep['status_code']} &middot; {ep['size_bytes']}B</span>
          {rec_html} {bypass_badge}
        </div>
        <div style="margin-bottom:8px">{pat_html}</div>
        {"<div style='color:#64748b;font-size:0.8em;margin-bottom:8px'>Exposure: " + exposure + "</div>" if exposure else ""}
        <details style="margin-top:8px">
          <summary style="color:#7dd3fc;cursor:pointer;font-size:0.85em;user-select:none">&#128203; Retrieved Data (click to expand)</summary>
          <pre style="background:#000;padding:14px;border-radius:4px;overflow-x:auto;font-size:0.78em;color:#a3e635;margin-top:8px;max-height:400px;overflow-y:auto">{data_escaped}</pre>
        </details>
      </div>"""

            if not sensitive and not bypass_hits:
                html += '<p class="empty">No unauthenticated API data retrieved.</p>'
            html += "</div></div>"

        html += f"""
</div>
<div class="footer">
  Generated by PreLoginScan v1.0 | BinaryGalaxys Security | For Authorized Penetration Testing Use Only<br>
  Engagement: {self.engagement_id} | {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
</div>
</body></html>"""

        with open(output_path, "w") as f:
            f.write(html)

    def _badge(self, sev: str) -> str:
        cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}.get(sev.upper(), "info")
        return f'<span class="badge badge-{cls}">{sev}</span>'

    def _bool_badge(self, val: bool) -> str:
        if val:
            return '<span class="badge badge-high">YES ⚠️</span>'
        return '<span class="badge badge-low">NO ✓</span>'

    def _escape(self, s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def generate(self, fmt: str, output_path: str):
        if fmt == "html":
            self.generate_html(output_path)
        elif fmt == "md":
            self.generate_markdown(output_path)
        else:
            self.generate_html(output_path)

    def generate_markdown(self, output_path: str):
        counts = self._count_findings()
        lines = [
            f"# PreLoginScan Report",
            f"**Target:** {self.target}  ",
            f"**Engagement:** {self.engagement_id}  ",
            f"**Date:** {self.timestamp[:19]} UTC  ",
            f"**Tool:** PreLoginScan v1.0 | BinaryGalaxys Security",
            "",
            "## Risk Summary",
            f"| Severity | Count |",
            f"|---|---|",
        ]
        for sev, count in counts.items():
            lines.append(f"| {sev} | {count} |")

        lines += ["", "## Secrets", ""]
        for f in self.modules.get("secrets", {}).get("findings", [])[:30]:
            lines.append(f"- **[{f['severity']}]** `{f['type']}` — `{f['match'][:80]}` in `{f['source']}`")

        lines += ["", "## GraphQL", ""]
        gql = self.modules.get("graphql", {})
        lines.append(f"- Endpoints: {len(gql.get('endpoints_found', []))}")
        lines.append(f"- Introspection: {'**ENABLED ⚠️**' if gql.get('introspection_enabled') else 'Disabled'}")
        for op in gql.get("sensitive_operations", [])[:20]:
            lines.append(f"- **[{op['risk']}]** `{op['operation']}` — {op['reason']}")

        with open(output_path, "w") as f:
            f.write("\n".join(lines))
