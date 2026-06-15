"""
Prompt Engine - Builds structured, context-aware prompts for each AI feature.
Extracts and summarizes scan findings before sending to the model.
"""

import json
from typing import Dict, List


SYSTEM_PROMPT = """You are a senior offensive security consultant and red team operator with 15+ years of experience in web application penetration testing, threat modeling, and adversarial simulation. You specialize in pre-authentication attack surface analysis.

You produce structured, actionable security analysis for professional pentest reports. Your output must be valid JSON only — no markdown, no preamble, no explanation outside the JSON structure. Every finding you reference must be grounded in the actual scan data provided."""


def extract_summary(scan_data: dict) -> dict:
    """Extract a compact, structured summary of findings for AI context."""
    modules = scan_data.get("modules", {})
    meta = scan_data.get("meta", {})
    summary = {
        "target": meta.get("target", "Unknown"),
        "engagement_id": meta.get("engagement_id", "N/A"),
        "timestamp": meta.get("timestamp", ""),
        "findings": {}
    }

    # Secrets
    if "secrets" in modules:
        sec = modules["secrets"]
        findings = sec.get("findings", [])
        summary["findings"]["secrets"] = {
            "total": sec.get("total", 0),
            "severity_summary": sec.get("severity_summary", {}),
            "top_findings": [
                {"type": f["type"], "severity": f["severity"], "source": f["source"]}
                for f in findings[:15]
            ]
        }

    # JS Analysis
    if "js_analysis" in modules:
        js = modules["js_analysis"]
        summary["findings"]["js_analysis"] = {
            "js_files": js.get("js_files_found", 0),
            "endpoints_discovered": js.get("discovered_endpoints", [])[:20],
            "frameworks": js.get("frameworks_detected", []),
            "source_maps_exposed": len(js.get("source_maps_exposed", [])),
            "cloud_urls": [c["url"] for c in js.get("cloud_storage_urls", [])[:5]],
            "sensitive_functions": js.get("sensitive_function_hints", [])[:10],
        }

    # GraphQL
    if "graphql" in modules:
        gql = modules["graphql"]
        summary["findings"]["graphql"] = {
            "endpoints_found": len(gql.get("endpoints_found", [])),
            "introspection_enabled": gql.get("introspection_enabled", False),
            "batch_queries_allowed": gql.get("batch_queries_allowed", False),
            "field_suggestions": gql.get("field_suggestions_enabled", False),
            "sensitive_operations": gql.get("sensitive_operations", [])[:15],
        }

    # Headers / CORS / Tokens
    if "headers_cors_tokens" in modules:
        hct = modules["headers_cors_tokens"]
        summary["findings"]["cors_headers"] = {
            "cors_misconfigs": hct.get("cors_findings", [])[:5],
            "missing_headers": hct.get("total_header_issues", 0),
            "cookie_issues": hct.get("total_cookie_issues", 0),
            "jwt_leaks": hct.get("token_leakage", [])[:5],
        }

    # PII
    if "pii" in modules:
        pii = modules["pii"]
        summary["findings"]["pii"] = {
            "total": pii.get("total", 0),
            "critical": pii.get("critical_count", 0),
            "types_found": pii.get("pii_types_found", []),
        }

    # Paths
    if "paths" in modules:
        paths = modules["paths"]
        summary["findings"]["paths"] = {
            "accessible_count": paths.get("accessible_200", 0),
            "critical_finds": [
                {"path": f["path"], "severity": f["severity"]}
                for f in paths.get("critical_finds", [])[:15]
            ],
            "openapi_exposed": bool(paths.get("openapi_spec")),
            "openapi_details": paths.get("openapi_spec"),
        }

    return summary


# ─── Feature Prompts ────────────────────────────────────────────────────────

def threat_model_prompt(summary: dict) -> str:
    return f"""Perform a STRIDE threat model on the pre-login attack surface findings below.

Scan Summary:
{json.dumps(summary, indent=2)}

Return a JSON object with this exact structure:
{{
  "threat_model": {{
    "target": "<target url>",
    "methodology": "STRIDE",
    "executive_summary": "<3-4 sentence risk overview for a CISO>",
    "stride_analysis": {{
      "Spoofing": {{
        "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
        "findings": ["<finding 1>", "<finding 2>"],
        "description": "<how spoofing is possible given these findings>"
      }},
      "Tampering": {{ ... }},
      "Repudiation": {{ ... }},
      "Information_Disclosure": {{ ... }},
      "Denial_of_Service": {{ ... }},
      "Elevation_of_Privilege": {{ ... }}
    }},
    "top_risks": [
      {{
        "rank": 1,
        "title": "<risk title>",
        "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
        "description": "<detailed description>",
        "business_impact": "<business impact>",
        "evidence": "<specific finding from scan data>"
      }}
    ],
    "attack_scenarios": [
      {{
        "scenario": "<scenario name>",
        "description": "<realistic attacker scenario>",
        "likelihood": "<HIGH|MEDIUM|LOW>",
        "impact": "<HIGH|MEDIUM|LOW>"
      }}
    ]
  }}
}}"""


def kill_chain_prompt(summary: dict) -> str:
    return f"""Build a realistic adversarial attack kill chain using ONLY the pre-authentication findings provided.

Scan Summary:
{json.dumps(summary, indent=2)}

Map the kill chain using the Unified Kill Chain model (18 phases). Only include phases that are achievable from these specific findings.

Return JSON with this exact structure:
{{
  "kill_chain": {{
    "target": "<target>",
    "model": "Unified Kill Chain",
    "overview": "<2-3 sentence summary of the complete attacker path>",
    "phases": [
      {{
        "phase_number": 1,
        "phase_name": "<e.g. Reconnaissance>",
        "ukc_phase": "<IN: Recon | THROUGH: Exploitation | OUT: Target Manipulation>",
        "attacker_action": "<what the attacker does>",
        "technique": "<specific technique name>",
        "mitre_technique_id": "<e.g. T1592>",
        "mitre_technique_name": "<MITRE name>",
        "evidence": "<specific finding from scan that enables this>",
        "tools": ["<tool1>", "<tool2>"],
        "commands": ["<example command if applicable>"]
      }}
    ],
    "total_phases": <number>,
    "estimated_time_to_compromise": "<e.g. 2-4 hours>",
    "attacker_skill_required": "<Script Kiddie|Intermediate|Advanced|Nation State>",
    "choke_points": [
      {{
        "phase": "<phase name>",
        "defensive_control": "<what would stop the attacker here>",
        "currently_missing": true
      }}
    ]
  }}
}}"""


def mitre_map_prompt(summary: dict) -> str:
    return f"""Map all pre-authentication findings to MITRE ATT&CK techniques and sub-techniques.

Scan Summary:
{json.dumps(summary, indent=2)}

Return JSON with this exact structure:
{{
  "mitre_mapping": {{
    "target": "<target>",
    "framework": "MITRE ATT&CK v14",
    "total_techniques": <number>,
    "tactics_covered": ["<tactic1>", "<tactic2>"],
    "mappings": [
      {{
        "finding_type": "<e.g. AWS Key Exposed>",
        "finding_severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
        "tactic": "<MITRE Tactic>",
        "technique_id": "<e.g. T1552.001>",
        "technique_name": "<Credentials in Files>",
        "sub_technique": "<if applicable>",
        "description": "<how this finding maps to this technique>",
        "detection_opportunity": "<how a defender could detect this>",
        "data_source": "<MITRE data source for detection>"
      }}
    ],
    "coverage_heatmap": {{
      "Reconnaissance": <count>,
      "Resource Development": <count>,
      "Initial Access": <count>,
      "Execution": <count>,
      "Persistence": <count>,
      "Privilege Escalation": <count>,
      "Defense Evasion": <count>,
      "Credential Access": <count>,
      "Discovery": <count>,
      "Lateral Movement": <count>,
      "Collection": <count>,
      "Exfiltration": <count>,
      "Impact": <count>
    }}
  }}
}}"""


def exploit_suggestion_prompt(summary: dict) -> str:
    return f"""Suggest specific exploitation paths for each pre-authentication finding, including PoC approaches.

Scan Summary:
{json.dumps(summary, indent=2)}

Return JSON:
{{
  "exploit_suggestions": [
    {{
      "finding": "<finding type>",
      "severity": "<severity>",
      "exploitability": "<Trivial|Easy|Moderate|Hard>",
      "exploitation_path": "<step by step exploitation>",
      "poc_approach": "<proof of concept approach>",
      "tools_recommended": ["<tool1>", "<tool2>"],
      "impact_if_exploited": "<what attacker gains>",
      "prerequisites": "<what attacker needs>",
      "cvss_estimate": "<e.g. 9.1>",
      "chained_with": "<other finding it chains with>"
    }}
  ],
  "highest_value_chain": {{
    "title": "<most impactful attack chain>",
    "steps": ["<step1>", "<step2>"],
    "end_result": "<what attacker achieves>"
  }}
}}"""


def remediation_prompt(summary: dict) -> str:
    return f"""Generate a prioritized remediation roadmap for all pre-authentication findings.

Scan Summary:
{json.dumps(summary, indent=2)}

Return JSON:
{{
  "remediation_roadmap": {{
    "executive_summary": "<brief summary for management>",
    "immediate_actions": [
      {{
        "priority": 1,
        "finding": "<finding>",
        "action": "<specific remediation action>",
        "effort": "<Hours|Days|Weeks>",
        "owner": "<Dev|SecOps|DevSecOps|Cloud Team>",
        "code_example": "<code snippet if applicable>"
      }}
    ],
    "short_term": [ ... ],
    "long_term": [ ... ],
    "estimated_total_effort": "<e.g. 3-5 developer days>",
    "risk_reduction": "<estimated % risk reduction after full remediation>"
  }}
}}"""


PROMPT_MAP = {
    "threat-model":  threat_model_prompt,
    "kill-chain":    kill_chain_prompt,
    "mitre":         mitre_map_prompt,
    "exploits":      exploit_suggestion_prompt,
    "remediation":   remediation_prompt,
}


def build_prompt(feature: str, summary: dict) -> str:
    fn = PROMPT_MAP.get(feature)
    if not fn:
        raise ValueError(f"Unknown feature: {feature}. Valid: {list(PROMPT_MAP.keys())}")
    return fn(summary)
