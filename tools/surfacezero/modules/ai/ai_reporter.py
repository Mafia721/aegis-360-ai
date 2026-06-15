"""
AI Report Generator - Generates the AI analysis section of the HTML report.
Merges scan findings + AI analysis into a single professional report.
"""

import json
from datetime import datetime
from typing import Dict, Optional


class AIReportSection:
    """Renders AI analysis results as HTML sections."""

    def __init__(self, ai_results: dict, scan_meta: dict):
        self.results = ai_results
        self.meta = scan_meta

    def _badge(self, sev: str) -> str:
        colors = {
            "CRITICAL": "#dc2626", "HIGH": "#ea580c",
            "MEDIUM": "#d97706", "LOW": "#65a30d", "INFO": "#0284c7"
        }
        color = colors.get(sev.upper(), "#6b7280")
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:700">{sev}</span>'

    def _escape(self, s) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def render_kill_chain(self, data: dict) -> str:
        kc = data.get("kill_chain", {})
        phases = kc.get("phases", [])
        choke = kc.get("choke_points", [])

        phase_rows = ""
        for p in phases:
            phase_rows += f"""
            <tr>
              <td><span style="background:#1e3a5f;color:#7dd3fc;padding:2px 8px;border-radius:12px;font-size:0.8em">{p.get('phase_number','')}</span></td>
              <td style="color:#fbbf24;font-weight:600">{self._escape(p.get('phase_name',''))}</td>
              <td>{self._escape(p.get('attacker_action',''))}</td>
              <td><code style="color:#7dd3fc">{self._escape(p.get('mitre_technique_id',''))}</code></td>
              <td style="color:#94a3b8;font-size:0.85em">{self._escape(p.get('technique_name',''))}</td>
              <td style="color:#64748b;font-size:0.8em">{self._escape(str(p.get('tools',[])))}</td>
            </tr>"""

        choke_html = ""
        for c in choke:
            choke_html += f"""
            <div style="background:#0f172a;border-left:3px solid #f59e0b;padding:10px 14px;margin:8px 0;border-radius:0 4px 4px 0">
              <strong style="color:#fbbf24">{self._escape(c.get('phase',''))}</strong><br>
              <span style="color:#94a3b8;font-size:0.85em">Missing control: {self._escape(c.get('defensive_control',''))}</span>
            </div>"""

        return f"""
<div class="section">
  <div class="section-header"><span>⚔️</span><h2>AI: Attack Kill Chain</h2>
    <span style="margin-left:auto;font-size:0.8em;color:#94a3b8">
      {len(phases)} phases · {self._escape(kc.get('estimated_time_to_compromise','N/A'))} · Skill: {self._escape(kc.get('attacker_skill_required','N/A'))}
    </span>
  </div>
  <div class="section-body">
    <div style="background:#0f172a;border-left:3px solid #dc2626;padding:12px 16px;margin-bottom:16px;border-radius:0 4px 4px 0">
      <strong style="color:#f87171">Attack Overview:</strong><br>
      <span style="color:#cbd5e1">{self._escape(kc.get('overview',''))}</span>
    </div>
    <table>
      <tr><th>#</th><th>Phase</th><th>Attacker Action</th><th>MITRE ID</th><th>Technique</th><th>Tools</th></tr>
      {phase_rows}
    </table>
    {"<h3 style='color:#fbbf24;margin:20px 0 8px'>⚡ Defensive Choke Points</h3>" + choke_html if choke else ""}
  </div>
</div>"""

    def render_threat_model(self, data: dict) -> str:
        tm = data.get("threat_model", {})
        stride = tm.get("stride_analysis", {})
        top_risks = tm.get("top_risks", [])

        stride_rows = ""
        risk_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d"}
        for cat, details in stride.items():
            if not isinstance(details, dict):
                continue
            risk = details.get("risk_level", "LOW")
            color = risk_colors.get(risk, "#6b7280")
            findings_list = "".join(f"<li style='color:#94a3b8;font-size:0.85em'>{self._escape(f)}</li>" for f in details.get("findings", []))
            stride_rows += f"""
            <tr>
              <td style="color:#fbbf24;font-weight:600">{cat.replace('_',' ')}</td>
              <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75em;font-weight:700">{risk}</span></td>
              <td style="color:#cbd5e1;font-size:0.9em">{self._escape(details.get('description',''))}</td>
              <td><ul style="margin:0;padding-left:16px">{findings_list}</ul></td>
            </tr>"""

        risk_cards = ""
        for r in top_risks[:5]:
            risk = r.get("severity", "LOW")
            color = risk_colors.get(risk, "#6b7280")
            risk_cards += f"""
            <div style="background:#0f172a;border:1px solid #334155;border-top:3px solid {color};border-radius:6px;padding:14px;margin:8px 0">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:12px;font-size:0.75em">#{r.get('rank','')} {risk}</span>
                <strong style="color:#f1f5f9">{self._escape(r.get('title',''))}</strong>
              </div>
              <p style="color:#94a3b8;font-size:0.875em;margin:0 0 6px">{self._escape(r.get('description',''))}</p>
              <p style="color:#64748b;font-size:0.8em;margin:0"><strong>Business Impact:</strong> {self._escape(r.get('business_impact',''))}</p>
              <p style="color:#64748b;font-size:0.8em;margin:4px 0 0"><strong>Evidence:</strong> <code>{self._escape(r.get('evidence',''))}</code></p>
            </div>"""

        return f"""
<div class="section">
  <div class="section-header"><span>🔍</span><h2>AI: Threat Model (STRIDE)</h2></div>
  <div class="section-body">
    <div style="background:#0f172a;border-left:3px solid #7c3aed;padding:12px 16px;margin-bottom:16px;border-radius:0 4px 4px 0">
      <strong style="color:#c4b5fd">Executive Summary:</strong><br>
      <span style="color:#cbd5e1">{self._escape(tm.get('executive_summary',''))}</span>
    </div>
    <table>
      <tr><th>STRIDE</th><th>Risk</th><th>Description</th><th>Contributing Findings</th></tr>
      {stride_rows}
    </table>
    {"<h3 style='color:#f1f5f9;margin:20px 0 10px'>Top Risks</h3>" + risk_cards if top_risks else ""}
  </div>
</div>"""

    def render_mitre(self, data: dict) -> str:
        mm = data.get("mitre_mapping", {})
        mappings = mm.get("mappings", [])
        heatmap = mm.get("coverage_heatmap", {})

        rows = ""
        sev_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#65a30d"}
        for m in mappings[:25]:
            sev = m.get("finding_severity", "LOW")
            color = sev_colors.get(sev, "#6b7280")
            rows += f"""
            <tr>
              <td style="color:#fbbf24">{self._escape(m.get('finding_type',''))}</td>
              <td><span style="background:{color};color:#fff;padding:1px 6px;border-radius:3px;font-size:0.75em">{sev}</span></td>
              <td><code style="color:#7dd3fc">{self._escape(m.get('technique_id',''))}</code></td>
              <td>{self._escape(m.get('technique_name',''))}</td>
              <td style="color:#94a3b8">{self._escape(m.get('tactic',''))}</td>
              <td style="color:#64748b;font-size:0.8em">{self._escape(m.get('detection_opportunity',''))[:80]}</td>
            </tr>"""

        heatmap_html = ""
        if heatmap:
            max_val = max(heatmap.values()) if heatmap.values() else 1
            for tactic, count in heatmap.items():
                if count > 0:
                    width = max(4, int((count / max(max_val, 1)) * 100))
                    heatmap_html += f"""
                    <div style="margin:4px 0;display:flex;align-items:center;gap:10px">
                      <span style="width:180px;font-size:0.8em;color:#94a3b8;text-align:right">{tactic}</span>
                      <div style="height:18px;width:{width}%;background:#dc2626;border-radius:2px;min-width:4px"></div>
                      <span style="font-size:0.8em;color:#64748b">{count}</span>
                    </div>"""

        return f"""
<div class="section">
  <div class="section-header"><span>🎯</span><h2>AI: MITRE ATT&CK Mapping</h2>
    <span style="margin-left:auto;font-size:0.8em;color:#94a3b8">{mm.get('total_techniques',0)} techniques · {len(mm.get('tactics_covered',[]))} tactics</span>
  </div>
  <div class="section-body">
    {f'<div style="margin-bottom:20px"><h3 style="color:#f1f5f9;margin-bottom:10px">Tactic Coverage Heatmap</h3>{heatmap_html}</div>' if heatmap_html else ''}
    <table>
      <tr><th>Finding</th><th>Severity</th><th>Technique ID</th><th>Technique</th><th>Tactic</th><th>Detection</th></tr>
      {rows}
    </table>
  </div>
</div>"""

    def render_exploits(self, data: dict) -> str:
        suggestions = data.get("exploit_suggestions", [])
        highest = data.get("highest_value_chain", {})

        cards = ""
        exploit_colors = {"Trivial": "#dc2626", "Easy": "#ea580c", "Moderate": "#d97706", "Hard": "#65a30d"}
        for s in suggestions[:10]:
            exp = s.get("exploitability", "Moderate")
            color = exploit_colors.get(exp, "#6b7280")
            tools = ", ".join(s.get("tools_recommended", []))
            cards += f"""
            <div style="background:#0f172a;border:1px solid #334155;border-left:4px solid {color};border-radius:6px;padding:14px;margin:8px 0">
              <div style="display:flex;gap:10px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
                <strong style="color:#f1f5f9">{self._escape(s.get('finding',''))}</strong>
                {self._badge(s.get('severity','LOW'))}
                <span style="background:{color};color:#fff;padding:1px 8px;border-radius:12px;font-size:0.75em">{exp}</span>
                <span style="color:#64748b;font-size:0.8em">CVSS ~{self._escape(str(s.get('cvss_estimate','')))}</span>
              </div>
              <p style="color:#94a3b8;font-size:0.875em;margin:0 0 6px"><strong>Exploitation Path:</strong> {self._escape(s.get('exploitation_path',''))}</p>
              <p style="color:#64748b;font-size:0.8em;margin:0 0 4px"><strong>PoC Approach:</strong> {self._escape(s.get('poc_approach',''))}</p>
              <p style="color:#64748b;font-size:0.8em;margin:0 0 4px"><strong>Impact:</strong> {self._escape(s.get('impact_if_exploited',''))}</p>
              {"<p style='color:#64748b;font-size:0.8em;margin:0'><strong>Tools:</strong> " + self._escape(tools) + "</p>" if tools else ""}
              {"<p style='color:#fbbf24;font-size:0.8em;margin:4px 0 0'><strong>Chains with:</strong> " + self._escape(s.get('chained_with','')) + "</p>" if s.get('chained_with') else ""}
            </div>"""

        chain_html = ""
        if highest:
            steps = "".join(f"<li style='color:#94a3b8;font-size:0.875em;margin:4px 0'>{self._escape(st)}</li>" for st in highest.get("steps", []))
            chain_html = f"""
            <div style="background:#0f172a;border:1px solid #dc2626;border-radius:6px;padding:16px;margin-bottom:16px">
              <h3 style="color:#f87171;margin:0 0 10px">🏆 Highest Value Attack Chain: {self._escape(highest.get('title',''))}</h3>
              <ol style="margin:0;padding-left:20px">{steps}</ol>
              <p style="color:#fbbf24;margin:10px 0 0;font-size:0.875em"><strong>End Result:</strong> {self._escape(highest.get('end_result',''))}</p>
            </div>"""

        return f"""
<div class="section">
  <div class="section-header"><span>💥</span><h2>AI: Exploit Suggestions</h2></div>
  <div class="section-body">
    {chain_html}
    {cards}
  </div>
</div>"""

    def render_remediation(self, data: dict) -> str:
        rr = data.get("remediation_roadmap", {})
        immediate = rr.get("immediate_actions", [])
        short = rr.get("short_term", [])
        long_ = rr.get("long_term", [])

        def render_actions(actions, border_color):
            html = ""
            for a in actions:
                code_block = f"""<pre style="background:#000;padding:10px;border-radius:4px;overflow-x:auto;font-size:0.8em;color:#7dd3fc;margin:8px 0 0">{self._escape(a.get('code_example',''))}</pre>""" if a.get("code_example") else ""
                html += f"""
                <div style="background:#0f172a;border-left:3px solid {border_color};padding:12px 14px;margin:6px 0;border-radius:0 4px 4px 0">
                  <div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">
                    <span style="color:#94a3b8;font-size:0.8em">Priority {a.get('priority','')}</span>
                    <strong style="color:#f1f5f9">{self._escape(a.get('finding',''))}</strong>
                    <span style="color:#64748b;font-size:0.8em">· {a.get('effort','')} · {a.get('owner','')}</span>
                  </div>
                  <p style="color:#94a3b8;font-size:0.875em;margin:0">{self._escape(a.get('action',''))}</p>
                  {code_block}
                </div>"""
            return html

        return f"""
<div class="section">
  <div class="section-header"><span>🛠️</span><h2>AI: Remediation Roadmap</h2>
    <span style="margin-left:auto;font-size:0.8em;color:#94a3b8">Est. effort: {self._escape(rr.get('estimated_total_effort','N/A'))} · Risk reduction: {self._escape(rr.get('risk_reduction','N/A'))}</span>
  </div>
  <div class="section-body">
    <div style="background:#0f172a;border-left:3px solid #7c3aed;padding:12px 16px;margin-bottom:16px;border-radius:0 4px 4px 0">
      {self._escape(rr.get('executive_summary',''))}
    </div>
    {"<h3 style='color:#dc2626;margin:16px 0 8px'>🚨 Immediate Actions</h3>" + render_actions(immediate, "#dc2626") if immediate else ""}
    {"<h3 style='color:#d97706;margin:16px 0 8px'>⚡ Short Term</h3>" + render_actions(short, "#d97706") if short else ""}
    {"<h3 style='color:#65a30d;margin:16px 0 8px'>📅 Long Term</h3>" + render_actions(long_, "#65a30d") if long_ else ""}
  </div>
</div>"""

    def render_all(self) -> str:
        """Render all available AI sections as HTML."""
        html = f"""
<div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);padding:20px 24px;margin:32px 0 0;border-top:2px solid #7c3aed">
  <h2 style="color:#c4b5fd;margin:0 0 4px">🤖 AI Security Analysis</h2>
  <p style="color:#64748b;margin:0;font-size:0.85em">Generated by AI Analyst · Model: {self._escape(self.meta.get('ai_model','Unknown'))}</p>
</div>"""

        render_map = {
            "threat-model": ("threat_model", self.render_threat_model),
            "kill-chain":   ("kill_chain",   self.render_kill_chain),
            "mitre":        ("mitre_mapping", self.render_mitre),
            "exploits":     ("exploit_suggestions", self.render_exploits),
            "remediation":  ("remediation_roadmap", self.render_remediation),
        }

        for feature, (key, renderer) in render_map.items():
            if feature in self.results:
                data = self.results[feature].get("data")
                if data:
                    html += renderer(data)

        return html
