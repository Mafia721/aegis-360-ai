"""
SurfaceZero Module - Pre-Authentication Attack Surface Enumeration
Blueprint for Aegis-360 AI server

Integrates SurfaceZero v2.1 by BinaryGalaxys Security.
Modules: JS analyzer, secrets, GraphQL, CORS/headers, paths, PII, API harvester.
AI: STRIDE threat model, kill chain, MITRE ATT&CK, exploit analysis, remediation.
"""

import json
import logging
import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# SurfaceZero binary in aegis-360-env
_VENV_BIN = Path(__file__).parent.parent / "aegis-360-env" / "bin"
SURFACEZERO_BIN = _VENV_BIN / "surfacezero"
SURFACEZERO_PY  = _VENV_BIN / "python3"

# Default output directory (under pentest_reports)
DEFAULT_OUTPUT = Path(__file__).parent.parent / "pentest_reports" / "surfacezero"
DEFAULT_OUTPUT.mkdir(parents=True, exist_ok=True)

surfacezero_bp = Blueprint("surfacezero", __name__, url_prefix="/api/surfacezero")


def _run(cmd: str, timeout: int = 600) -> dict:
    """Execute a shell command and return structured output."""
    env = os.environ.copy()
    env["PATH"] = str(_VENV_BIN) + ":" + env.get("PATH", "")
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return {
            "success": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": cmd,
            "timestamp": datetime.now().isoformat(),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Command timed out after {timeout}s",
            "command": cmd,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": cmd,
            "timestamp": datetime.now().isoformat(),
        }


def _safe_str(value: str) -> str:
    """Safely quote a shell argument."""
    return shlex.quote(str(value))


# ============================================================================
# SCAN ENDPOINT
# ============================================================================

@surfacezero_bp.route("/scan", methods=["POST"])
def surfacezero_scan():
    """
    Run a full SurfaceZero pre-authentication surface scan.

    POST JSON:
      target        (required) — Target URL, e.g. https://app.example.com
      output        — Output directory [pentest_reports/surfacezero]
      threads       — Concurrent threads [10]
      timeout       — Request timeout seconds [15]
      proxy         — Proxy URL e.g. http://127.0.0.1:8080
      skip_ssl      — Disable SSL verification [false]
      cookie        — Cookie header value
      modules       — Comma-separated: all | secrets,js,graphql,cors,headers,paths,pii,api_harvest
      aggressive    — Auth bypass + HTTP method testing [false]
      engagement_id — Tag for report (e.g. PT36020)
      ai_analyze    — Chain AI analysis after scan [false]
      ai_model      — AI model: claude | deepseek | gpt4 | gemini | ollama:llama3 [claude]
      ai_features   — Comma-separated: threat-model,kill-chain,mitre,exploits,remediation
      api_key       — AI API key (uses env var if not provided)
      verbose       — Verbose output [false]
    """
    try:
        p = request.json or {}
        target = p.get("target", "").strip()
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400

        output      = p.get("output", str(DEFAULT_OUTPUT))
        threads     = int(p.get("threads", 10))
        timeout_sec = int(p.get("timeout", 15))
        proxy       = p.get("proxy", "")
        skip_ssl    = bool(p.get("skip_ssl", False))
        cookie      = p.get("cookie", "")
        modules     = p.get("modules", "all")
        aggressive  = bool(p.get("aggressive", False))
        eng_id      = p.get("engagement_id", "")
        ai_analyze  = bool(p.get("ai_analyze", False))
        ai_model    = p.get("ai_model", "claude")
        ai_features = p.get("ai_features", "threat-model,kill-chain,mitre")
        api_key     = p.get("api_key", "")
        verbose     = bool(p.get("verbose", False))

        # Build command
        cmd = (
            f"{SURFACEZERO_BIN} scan"
            f" --target {_safe_str(target)}"
            f" --output {_safe_str(output)}"
            f" --threads {threads}"
            f" --timeout {timeout_sec}"
            f" --modules {_safe_str(modules)}"
        )

        if proxy:
            cmd += f" --proxy {_safe_str(proxy)}"
        if skip_ssl:
            cmd += " --skip-ssl"
        if cookie:
            cmd += f" --cookie {_safe_str(cookie)}"
        if aggressive:
            cmd += " --aggressive"
        if eng_id:
            cmd += f" --engagement-id {_safe_str(eng_id)}"
        if ai_analyze:
            cmd += f" --ai-analyze --ai-model {_safe_str(ai_model)}"
            cmd += f" --ai-features {_safe_str(ai_features)}"
        if api_key:
            cmd += f" --api-key {_safe_str(api_key)}"
        if verbose:
            cmd += " --verbose"

        logger.info("🔍 [SurfaceZero] Starting scan: %s", target)
        result = _run(cmd, timeout=max(timeout_sec * 60, 300))

        if result.get("success"):
            logger.info("✅ [SurfaceZero] Scan completed for %s", target)
        else:
            logger.error("❌ [SurfaceZero] Scan failed for %s: %s",
                         target, result.get("error", result.get("stderr", "")[:200]))

        result["target"] = target
        result["output_dir"] = output
        return jsonify(result)

    except Exception as e:
        logger.error("💥 SurfaceZero scan error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# ANALYZE ENDPOINT
# ============================================================================

@surfacezero_bp.route("/analyze", methods=["POST"])
def surfacezero_analyze():
    """
    Run AI threat analysis on an existing SurfaceZero scan JSON.

    POST JSON:
      input         (required) — Path to scan JSON file
      model         — AI model: claude | deepseek | gpt4 | gemini | ollama:llama3 [claude]
      features      — Comma-separated: threat-model,kill-chain,mitre,exploits,remediation
      output        — HTML report output path
      api_key       — AI API key (uses env var if not provided)
      ollama_host   — Ollama URL [http://localhost:11434]
    """
    try:
        p = request.json or {}
        input_path = p.get("input", "").strip()
        if not input_path:
            return jsonify({"success": False, "error": "input (scan JSON path) is required"}), 400

        model       = p.get("model", "claude")
        features    = p.get("features", "threat-model,kill-chain,mitre,exploits,remediation")
        output_path = p.get("output", "")
        api_key     = p.get("api_key", "")
        ollama_host = p.get("ollama_host", "")

        cmd = (
            f"{SURFACEZERO_BIN} analyze"
            f" --input {_safe_str(input_path)}"
            f" --model {_safe_str(model)}"
            f" --features {_safe_str(features)}"
        )

        if output_path:
            cmd += f" --output {_safe_str(output_path)}"
        if api_key:
            cmd += f" --api-key {_safe_str(api_key)}"
        if ollama_host:
            cmd += f" --ollama-host {_safe_str(ollama_host)}"

        logger.info("🤖 [SurfaceZero] AI analysis: model=%s features=%s", model, features)
        result = _run(cmd, timeout=300)

        if result.get("success"):
            logger.info("✅ [SurfaceZero] AI analysis completed (model=%s)", model)
        else:
            logger.error("❌ [SurfaceZero] AI analysis failed: %s",
                         result.get("error", result.get("stderr", "")[:200]))

        result["input"] = input_path
        result["model"] = model
        return jsonify(result)

    except Exception as e:
        logger.error("💥 SurfaceZero analyze error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# REPORT ENDPOINT
# ============================================================================

@surfacezero_bp.route("/report", methods=["POST"])
def surfacezero_report():
    """
    Generate a formatted report from a SurfaceZero scan JSON.

    POST JSON:
      input    (required) — Path to scan JSON file
      format   — html | md | json [html]
      output   — Output file path
    """
    try:
        p = request.json or {}
        input_path = p.get("input", "").strip()
        if not input_path:
            return jsonify({"success": False, "error": "input (scan JSON path) is required"}), 400

        fmt         = p.get("format", "html")
        output_path = p.get("output", "")

        cmd = (
            f"{SURFACEZERO_BIN} report"
            f" --input {_safe_str(input_path)}"
            f" --format {_safe_str(fmt)}"
        )
        if output_path:
            cmd += f" --output {_safe_str(output_path)}"

        logger.info("📄 [SurfaceZero] Generating %s report from %s", fmt.upper(), input_path)
        result = _run(cmd, timeout=120)

        if result.get("success"):
            logger.info("✅ [SurfaceZero] %s report generated", fmt.upper())
        else:
            logger.error("❌ [SurfaceZero] Report generation failed")

        result["input"] = input_path
        result["format"] = fmt
        return jsonify(result)

    except Exception as e:
        logger.error("💥 SurfaceZero report error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# MODULE-SPECIFIC SCANS
# ============================================================================

@surfacezero_bp.route("/scan/secrets", methods=["POST"])
def surfacezero_secrets():
    """Quick secrets-only scan (AWS/GCP/Azure keys, JWTs, DB URIs, tokens — 45 patterns)."""
    try:
        p = request.json or {}
        target = p.get("target", "").strip()
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400

        output  = p.get("output", str(DEFAULT_OUTPUT))
        proxy   = p.get("proxy", "")
        skip_ssl = bool(p.get("skip_ssl", False))

        cmd = (
            f"{SURFACEZERO_BIN} scan"
            f" --target {_safe_str(target)}"
            f" --output {_safe_str(output)}"
            f" --modules secrets,js"
        )
        if proxy:
            cmd += f" --proxy {_safe_str(proxy)}"
        if skip_ssl:
            cmd += " --skip-ssl"

        logger.info("🔑 [SurfaceZero] Secrets scan: %s", target)
        result = _run(cmd, timeout=180)
        result["target"] = target
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@surfacezero_bp.route("/scan/api-harvest", methods=["POST"])
def surfacezero_api_harvest():
    """API data harvester — 114 probes, auth bypass headers, sensitive data detection."""
    try:
        p = request.json or {}
        target = p.get("target", "").strip()
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400

        output     = p.get("output", str(DEFAULT_OUTPUT))
        aggressive = bool(p.get("aggressive", True))
        proxy      = p.get("proxy", "")
        skip_ssl   = bool(p.get("skip_ssl", False))

        cmd = (
            f"{SURFACEZERO_BIN} scan"
            f" --target {_safe_str(target)}"
            f" --output {_safe_str(output)}"
            f" --modules api_harvest,paths"
        )
        if aggressive:
            cmd += " --aggressive"
        if proxy:
            cmd += f" --proxy {_safe_str(proxy)}"
        if skip_ssl:
            cmd += " --skip-ssl"

        logger.info("🌐 [SurfaceZero] API harvest: %s (aggressive=%s)", target, aggressive)
        result = _run(cmd, timeout=300)
        result["target"] = target
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@surfacezero_bp.route("/scan/graphql", methods=["POST"])
def surfacezero_graphql():
    """GraphQL scanner — introspection, mutations, batch queries, field suggestions."""
    try:
        p = request.json or {}
        target = p.get("target", "").strip()
        if not target:
            return jsonify({"success": False, "error": "target is required"}), 400

        output   = p.get("output", str(DEFAULT_OUTPUT))
        proxy    = p.get("proxy", "")
        skip_ssl = bool(p.get("skip_ssl", False))

        cmd = (
            f"{SURFACEZERO_BIN} scan"
            f" --target {_safe_str(target)}"
            f" --output {_safe_str(output)}"
            f" --modules graphql"
        )
        if proxy:
            cmd += f" --proxy {_safe_str(proxy)}"
        if skip_ssl:
            cmd += " --skip-ssl"

        logger.info("🔷 [SurfaceZero] GraphQL scan: %s", target)
        result = _run(cmd, timeout=120)
        result["target"] = target
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ============================================================================
# STATUS ENDPOINT
# ============================================================================

@surfacezero_bp.route("/status", methods=["GET"])
def surfacezero_status():
    """Check SurfaceZero installation and version."""
    result = _run(f"{SURFACEZERO_BIN} --version", timeout=10)
    version = result.get("stdout", "").strip() or result.get("stderr", "").strip()
    return jsonify({
        "installed": result.get("success", False),
        "version": version,
        "binary": str(SURFACEZERO_BIN),
        "output_dir": str(DEFAULT_OUTPUT),
        "endpoints": [
            "/api/surfacezero/scan",
            "/api/surfacezero/scan/secrets",
            "/api/surfacezero/scan/api-harvest",
            "/api/surfacezero/scan/graphql",
            "/api/surfacezero/analyze",
            "/api/surfacezero/report",
            "/api/surfacezero/status",
        ],
        "modules": [
            "js", "secrets", "graphql", "cors", "headers",
            "paths", "pii", "api_harvest", "tokens", "cookies",
        ],
        "ai_features": [
            "threat-model", "kill-chain", "mitre", "exploits", "remediation",
        ],
        "timestamp": datetime.now().isoformat(),
    })
