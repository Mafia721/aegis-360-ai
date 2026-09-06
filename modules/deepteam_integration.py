"""
DeepTeam Module - LLM Red-Teaming & Adversarial Safety Testing
Blueprint for Aegis-360 AI server

Integrates github.com/confident-ai/deepteam
40+ vulnerability types, 20+ single/multi-turn attacks, scoring & reporting.
"""

import asyncio
import json
import logging
import os
import threading
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

deepteam_bp = Blueprint("deepteam", __name__, url_prefix="/api/deepteam")

# In-memory job store for async scans
_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()

# ─── Catalog ─────────────────────────────────────────────────────────────────

VULNERABILITY_CATALOG = {
    # Safety
    "Toxicity": "Profanity, insults, threats, mockery",
    "Bias": "Religion, politics, gender, race bias",
    "IllegalActivity": "Weapons, drugs, violent crimes, cybercrime",
    "GraphicContent": "Sexual, graphic, or pornographic content",
    "PersonalSafety": "Bullying, self-harm, unsafe practices",
    "ChildProtection": "Age verification, data privacy, exposure",
    "Ethics": "Moral integrity, harm prevention",
    # Privacy / Information
    "PIILeakage": "API access, direct disclosure, session leak, social manipulation",
    "PromptLeakage": "Secrets/credentials, instructions, guard exposure",
    "Misinformation": "Factual errors, unsupported claims",
    "Hallucination": "Fake citations, APIs, entities, statistics",
    "IntellectualProperty": "Copyright, trademark, patent disclosure",
    "Competition": "Competitor mention, market manipulation",
    # Security
    "SQLInjection": "Blind, union-based, error-based SQL injection",
    "SSRF": "Internal service access, cloud metadata, port scanning",
    "ShellInjection": "Command injection, shell escape sequences",
    "DebugAccess": "Debug mode bypass, dev endpoint access",
    "SystemReconnaissance": "File metadata, DB schema, retrieval config",
    "UnexpectedCodeExecution": "Unauthorized code/shell execution, eval usage",
    # Access Control
    "RBAC": "Role bypass, privilege escalation, unauthorized role assumption",
    "BOLA": "Object access bypass, cross-customer access",
    "BFLA": "Privilege escalation, function/authorization bypass",
    # Agentic
    "ExcessiveAgency": "Functionality, permissions, autonomy overreach",
    "ExploitToolAgent": "Tool exploitation in agent workflows",
    "ToolOrchestrationAbuse": "Abuse of tool orchestration",
    "ToolMetadataPoisoning": "Poisoning tool metadata",
    "GoalTheft": "Goal/objective hijacking",
    "AgentIdentityAbuse": "Identity spoofing in multi-agent systems",
    "AutonomousAgentDrift": "Unintended agent behavior drift",
    "RecursiveHijacking": "Recursive instruction hijacking",
    "InsecureInterAgentCommunication": "Insecure messaging between agents",
    "ExternalSystemAbuse": "Abuse of external integrations",
    "IndirectInstruction": "Indirect prompt injection via external data",
    "CrossContextRetrieval": "Cross-context data retrieval attacks",
}

SINGLE_TURN_ATTACKS = [
    "PromptInjection", "Roleplay", "MathProblem", "Base64", "ROT13",
    "Leetspeak", "Multilingual", "AuthorityEscalation", "PermissionEscalation",
    "SystemOverride", "InputBypass", "GoalRedirection", "ContextFlooding",
    "ContextPoisoning", "SyntheticContextInjection", "EmbeddedInstructionJSON",
    "EmotionalManipulation", "AdversarialPoetry", "CharacterStream",
    "LinguisticConfusion", "GrayBox", "PromptProbing",
]

MULTI_TURN_ATTACKS = [
    "LinearJailbreaking", "TreeJailbreaking", "CrescendoJailbreaking",
    "SequentialJailbreak", "BadLikertJudge",
]

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _build_model_callback(params: dict):
    """Build a deepteam model_callback from request parameters."""
    endpoint_url = params.get("endpoint_url", "")
    api_key = params.get("api_key", os.environ.get("OPENAI_API_KEY", ""))
    model = params.get("model", "gpt-4o-mini")
    system_prompt = params.get("system_prompt", "")
    provider = params.get("provider", "openai").lower()
    timeout = int(params.get("request_timeout", 60))

    if endpoint_url:
        # Generic HTTP endpoint: POST {"prompt": ...} → {"response": ...}
        def http_callback(prompt: str, turns=None) -> str:
            try:
                payload = {"prompt": prompt}
                if system_prompt:
                    payload["system_prompt"] = system_prompt
                resp = requests.post(
                    endpoint_url,
                    json=payload,
                    headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                return data.get("response", data.get("content", str(data)))
            except Exception as exc:
                logger.warning(f"model_callback HTTP error: {exc}")
                return f"[ERROR: {exc}]"
        return http_callback

    # OpenAI-compatible callback using the openai SDK
    try:
        from openai import OpenAI
        base_url = params.get("base_url", None)
        client = OpenAI(
            api_key=api_key or "sk-placeholder",
            base_url=base_url if base_url else None,
        )
        messages_base = []
        if system_prompt:
            messages_base = [{"role": "system", "content": system_prompt}]

        def openai_callback(prompt: str, turns=None) -> str:
            try:
                msgs = messages_base + [{"role": "user", "content": prompt}]
                resp = client.chat.completions.create(
                    model=model,
                    messages=msgs,
                    timeout=timeout,
                )
                return resp.choices[0].message.content or ""
            except Exception as exc:
                logger.warning(f"model_callback OpenAI error: {exc}")
                return f"[ERROR: {exc}]"
        return openai_callback

    except ImportError:
        raise RuntimeError("openai package not found; provide endpoint_url instead")


def _resolve_vulnerabilities(vuln_names: List[str], purpose: str = "") -> list:
    """Import and instantiate vulnerability classes by name."""
    import deepteam.vulnerabilities as V
    result = []
    for name in vuln_names:
        cls = getattr(V, name, None)
        if cls is None:
            logger.warning(f"Unknown vulnerability: {name} — skipping")
            continue
        try:
            kwargs = {}
            if purpose:
                kwargs["purpose"] = purpose
            result.append(cls(**kwargs))
        except Exception as exc:
            logger.warning(f"Could not instantiate {name}: {exc}")
    return result


def _resolve_attacks(attack_names: List[str]) -> list:
    """Import and instantiate attack classes by name."""
    import deepteam.attacks.single_turn as ST
    import deepteam.attacks.multi_turn as MT
    result = []
    for name in attack_names:
        cls = getattr(ST, name, None) or getattr(MT, name, None)
        if cls is None:
            logger.warning(f"Unknown attack: {name} — skipping")
            continue
        try:
            result.append(cls())
        except Exception as exc:
            logger.warning(f"Could not instantiate attack {name}: {exc}")
    return result


def _serialise_results(results) -> Dict[str, Any]:
    """Convert deepteam results to a JSON-safe dict."""
    try:
        if hasattr(results, "__dict__"):
            raw = results.__dict__
        elif hasattr(results, "model_dump"):
            raw = results.model_dump()
        else:
            raw = {"raw": str(results)}

        def _safe(obj):
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if isinstance(obj, dict):
                return {k: _safe(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [_safe(i) for i in obj]
            if hasattr(obj, "model_dump"):
                return _safe(obj.model_dump())
            if hasattr(obj, "__dict__"):
                return _safe(obj.__dict__)
            return str(obj)

        return _safe(raw)
    except Exception as exc:
        return {"serialization_error": str(exc)}


def _run_scan(job_id: str, params: dict):
    """Execute a deepteam red team scan in a background thread."""
    try:
        from deepteam.red_teamer import RedTeamer

        _update_job(job_id, "running", progress="Building target callback")

        callback = _build_model_callback(params)

        vuln_names = params.get("vulnerabilities", ["Toxicity", "PIILeakage", "PromptLeakage"])
        if isinstance(vuln_names, str):
            vuln_names = [v.strip() for v in vuln_names.split(",")]

        attack_names = params.get("attacks", ["PromptInjection", "Roleplay"])
        if isinstance(attack_names, str):
            attack_names = [a.strip() for a in attack_names.split(",")]

        purpose = params.get("target_purpose", "")
        vulns = _resolve_vulnerabilities(vuln_names, purpose)
        attack_objs = _resolve_attacks(attack_names)

        if not vulns:
            _update_job(job_id, "failed", error="No valid vulnerabilities specified")
            return
        if not attack_objs:
            _update_job(job_id, "failed", error="No valid attacks specified")
            return

        simulator_model = params.get("simulator_model", "gpt-3.5-turbo-0125")
        evaluation_model = params.get("evaluation_model", "gpt-4o")
        attacks_per_vuln = int(params.get("attacks_per_vulnerability", 1))
        max_concurrent = int(params.get("max_concurrent", 5))

        red_teamer = RedTeamer(
            simulator_model=simulator_model,
            evaluation_model=evaluation_model,
            target_purpose=purpose,
            max_concurrent=max_concurrent,
        )

        _update_job(job_id, "running", progress="Running red team evaluation")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            results = loop.run_until_complete(
                red_teamer.a_red_team(
                    model_callback=callback,
                    vulnerabilities=vulns,
                    attacks=attack_objs,
                    attacks_per_vulnerability_type=attacks_per_vuln,
                )
            ) if hasattr(red_teamer, "a_red_team") else red_teamer.red_team(
                model_callback=callback,
                vulnerabilities=vulns,
                attacks=attack_objs,
                attacks_per_vulnerability_type=attacks_per_vuln,
            )
        finally:
            loop.close()

        serialised = _serialise_results(results)
        _update_job(job_id, "completed", result=serialised)
        logger.info(f"✅ DeepTeam scan {job_id} completed")

    except Exception as exc:
        logger.error(f"💥 DeepTeam scan {job_id} failed: {exc}", exc_info=True)
        _update_job(job_id, "failed", error=str(exc))


def _update_job(job_id: str, status: str, **kwargs):
    with _jobs_lock:
        if job_id not in _jobs:
            _jobs[job_id] = {}
        _jobs[job_id].update({"status": status, "updated_at": datetime.now().isoformat(), **kwargs})


# ─── Routes ──────────────────────────────────────────────────────────────────

@deepteam_bp.route("/scan", methods=["POST"])
def scan():
    """
    Synchronously run a DeepTeam LLM red-team scan (blocks until complete).

    Target specification — provide one of:
      endpoint_url (str): HTTP endpoint to POST prompts to ({"prompt":…} → {"response":…})
      model (str): OpenAI-compatible model name (requires OPENAI_API_KEY or api_key)
      base_url (str): Custom OpenAI-compatible base URL (Ollama, LiteLLM, etc.)

    Optional:
      api_key (str): Override API key for the target provider
      system_prompt (str): System prompt for the target LLM
      target_purpose (str): Describe what the target LLM is for (improves attack quality)
      provider (str): "openai" | "anthropic" (default: openai)
      request_timeout (int): Per-request timeout in seconds (default: 60)

    Attack configuration:
      vulnerabilities (list|str): Comma-separated vulnerability names to test
        Default: Toxicity,PIILeakage,PromptLeakage
        Available: see GET /api/deepteam/vulnerabilities
      attacks (list|str): Comma-separated attack names to apply
        Default: PromptInjection,Roleplay
        Available: see GET /api/deepteam/attacks
      attacks_per_vulnerability (int): Attacks per vulnerability type (default: 1)

    Scoring models (require OPENAI_API_KEY):
      simulator_model (str): Model for generating attack variants (default: gpt-3.5-turbo-0125)
      evaluation_model (str): Model for scoring responses (default: gpt-4o)
      max_concurrent (int): Max concurrent evaluations (default: 5)
    """
    params = request.json or {}
    if not params.get("endpoint_url") and not params.get("model") and not params.get("api_key"):
        return jsonify({"error": "Provide endpoint_url or model+api_key to specify the target LLM"}), 400

    job_id = str(uuid.uuid4())
    _update_job(job_id, "running", params_summary={
        "vulnerabilities": params.get("vulnerabilities"),
        "attacks": params.get("attacks"),
        "target": params.get("endpoint_url") or params.get("model", ""),
    })

    thread = threading.Thread(target=_run_scan, args=(job_id, params), daemon=True)
    thread.start()
    thread.join(timeout=int(params.get("scan_timeout", 600)))

    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if job.get("status") == "running":
        job["note"] = "Scan still running; poll /api/deepteam/status/<job_id>"

    return jsonify({"job_id": job_id, **job})


@deepteam_bp.route("/scan-async", methods=["POST"])
def scan_async():
    """
    Submit a DeepTeam scan as a background job and return a job_id immediately.
    Poll /api/deepteam/status/<job_id> for completion.

    Same parameters as POST /api/deepteam/scan.
    """
    params = request.json or {}
    if not params.get("endpoint_url") and not params.get("model") and not params.get("api_key"):
        return jsonify({"error": "Provide endpoint_url or model+api_key to specify the target LLM"}), 400

    job_id = str(uuid.uuid4())
    _update_job(job_id, "queued", params_summary={
        "vulnerabilities": params.get("vulnerabilities"),
        "attacks": params.get("attacks"),
        "target": params.get("endpoint_url") or params.get("model", ""),
        "submitted_at": datetime.now().isoformat(),
    })

    thread = threading.Thread(target=_run_scan, args=(job_id, params), daemon=True)
    thread.start()

    logger.info(f"📋 DeepTeam scan {job_id} submitted")
    return jsonify({"job_id": job_id, "status": "queued", "poll_url": f"/api/deepteam/status/{job_id}"})


@deepteam_bp.route("/status/<job_id>", methods=["GET"])
def status(job_id: str):
    """Return the current status of a submitted DeepTeam scan job."""
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return jsonify({"error": f"Job {job_id} not found"}), 404

    return jsonify({"job_id": job_id, **job})


@deepteam_bp.route("/report/<job_id>", methods=["GET"])
def report(job_id: str):
    """Return the full result of a completed DeepTeam scan job."""
    with _jobs_lock:
        job = dict(_jobs.get(job_id, {}))

    if not job:
        return jsonify({"error": f"Job {job_id} not found"}), 404
    if job.get("status") != "completed":
        return jsonify({"error": f"Job {job_id} status is '{job.get('status')}', not completed"}), 409

    return jsonify({"job_id": job_id, **job})


@deepteam_bp.route("/jobs", methods=["GET"])
def list_jobs():
    """List all submitted DeepTeam scan jobs with their status."""
    with _jobs_lock:
        jobs = {jid: {k: v for k, v in j.items() if k != "result"} for jid, j in _jobs.items()}
    return jsonify({"jobs": jobs, "count": len(jobs)})


@deepteam_bp.route("/vulnerabilities", methods=["GET"])
def list_vulnerabilities():
    """List all supported DeepTeam vulnerability types and their descriptions."""
    return jsonify({
        "vulnerabilities": VULNERABILITY_CATALOG,
        "count": len(VULNERABILITY_CATALOG),
        "categories": {
            "safety": ["Toxicity", "Bias", "IllegalActivity", "GraphicContent", "PersonalSafety", "ChildProtection", "Ethics"],
            "privacy_information": ["PIILeakage", "PromptLeakage", "Misinformation", "Hallucination", "IntellectualProperty", "Competition"],
            "security": ["SQLInjection", "SSRF", "ShellInjection", "DebugAccess", "SystemReconnaissance", "UnexpectedCodeExecution"],
            "access_control": ["RBAC", "BOLA", "BFLA"],
            "agentic": ["ExcessiveAgency", "ExploitToolAgent", "ToolOrchestrationAbuse", "ToolMetadataPoisoning",
                        "GoalTheft", "AgentIdentityAbuse", "AutonomousAgentDrift", "RecursiveHijacking",
                        "InsecureInterAgentCommunication", "ExternalSystemAbuse", "IndirectInstruction", "CrossContextRetrieval"],
        },
    })


@deepteam_bp.route("/attacks", methods=["GET"])
def list_attacks():
    """List all supported DeepTeam attack methods."""
    return jsonify({
        "single_turn": SINGLE_TURN_ATTACKS,
        "multi_turn": MULTI_TURN_ATTACKS,
        "all": SINGLE_TURN_ATTACKS + MULTI_TURN_ATTACKS,
        "count": len(SINGLE_TURN_ATTACKS) + len(MULTI_TURN_ATTACKS),
    })


@deepteam_bp.route("/version", methods=["GET"])
def version():
    """Return the installed deepteam version."""
    try:
        import deepteam
        ver = getattr(deepteam, "__version__", None)
        if ver is None:
            from deepteam._version import __version__ as ver
        return jsonify({"version": ver, "package": "deepteam", "source": "confident-ai/deepteam"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
