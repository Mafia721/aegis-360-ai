#!/usr/bin/env python3
"""
Aegis-360 AI — Multi-Model Orchestration Engine
================================================
Implements a strictly-phased security assessment workflow with enforced model separation.

Workflow sequence:
  START → RECON (DeepSeek V4 Pro) → ENUMERATION (DeepSeek V4 Pro)
        → VULNERABILITY_ANALYSIS (DeepSeek V4 Pro) → VALIDATION_GATE
        → EXPLOITATION (Claude API) → REPORTING (Claude API) → END

Model responsibilities:
  Claude Code      : Central coordinator — planning, delegation, state management
  DeepSeek V4 Pro  : Recon, enumeration, vulnerability analysis, scan optimization
  Claude API       : Exploitation phase + final report generation (ONLY)

Phase guards prevent Claude API from being invoked before the validation gate clears.
All model handoffs are logged with timestamps and decision context.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request

# ---------------------------------------------------------------------------
# Optional SDK imports
# ---------------------------------------------------------------------------
try:
    from openai import OpenAI as _OpenAI
    _OPENAI_SDK_OK = True
except ImportError:
    _OPENAI_SDK_OK = False

try:
    import anthropic as _anthropic_sdk
    _ANTHROPIC_SDK_OK = True
except ImportError:
    _ANTHROPIC_SDK_OK = False

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).parent
_STATE_DIR = _BASE_DIR / "workflow_states"
_REPORT_DIR = _BASE_DIR / "pentest_reports"
_STATE_DIR.mkdir(exist_ok=True)
_REPORT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WorkflowPhase(str, Enum):
    START                 = "START"
    RECON                 = "RECON"
    ENUMERATION           = "ENUMERATION"
    VULNERABILITY_ANALYSIS = "VULNERABILITY_ANALYSIS"
    VALIDATION_GATE       = "VALIDATION_GATE"
    EXPLOITATION          = "EXPLOITATION"
    REPORTING             = "REPORTING"
    END                   = "END"


class PhaseStatus(str, Enum):
    PENDING     = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"
    FAILED      = "failed"
    SKIPPED     = "skipped"


# Ordered list of phases
PHASE_ORDER: List[WorkflowPhase] = [
    WorkflowPhase.START,
    WorkflowPhase.RECON,
    WorkflowPhase.ENUMERATION,
    WorkflowPhase.VULNERABILITY_ANALYSIS,
    WorkflowPhase.VALIDATION_GATE,
    WorkflowPhase.EXPLOITATION,
    WorkflowPhase.REPORTING,
    WorkflowPhase.END,
]

# All active phases handled by Claude (Claude Code handles all phases)
DEEPSEEK_PHASES: set = set()

# Phases handled by Claude API
CLAUDE_PHASES = {
    WorkflowPhase.RECON,
    WorkflowPhase.ENUMERATION,
    WorkflowPhase.VULNERABILITY_ANALYSIS,
    WorkflowPhase.EXPLOITATION,
    WorkflowPhase.REPORTING,
}

# No phases forbidden for Claude — Claude Code handles all phases
CLAUDE_FORBIDDEN_PHASES: set = set()

# All phases that must be COMPLETED before the gate can open
PRE_EXPLOITATION_PHASES = [
    WorkflowPhase.RECON,
    WorkflowPhase.ENUMERATION,
    WorkflowPhase.VULNERABILITY_ANALYSIS,
]

# Human-readable model names for logs
MODEL_LABELS = {
    "orchestrator": "Claude Code (Orchestrator)",
    "claude-api":   "Claude Code (claude-sonnet-4-6)",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PhaseViolationError(RuntimeError):
    """Raised when Claude API is invoked in a forbidden phase."""


class PhaseGateError(RuntimeError):
    """Raised when the validation gate fails — pre-exploitation phases incomplete."""


class WorkflowNotFoundError(KeyError):
    """Raised when a workflow_id does not exist."""


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

_DEEPSEEK_SYSTEM = """\
You are DeepSeek V4 Pro, the dedicated reconnaissance and vulnerability analysis \
engine embedded in Aegis-360 AI, a professional penetration testing platform.

YOUR SOLE RESPONSIBILITY covers three sequential phases:
  1. RECON         — passive/active reconnaissance, OSINT, subdomain enumeration,
                     port scanning strategy, technology fingerprinting
  2. ENUMERATION   — service enumeration, directory/file discovery, parameter analysis,
                     authentication surface mapping, API endpoint discovery
  3. VULNERABILITY_ANALYSIS — triage, CVSS scoring, exploitability assessment,
                     prioritized vulnerability list, exploitation readiness flag

For every task you MUST:
  • Recommend precise tool commands with optimised flags for the target.
  • Analyse raw tool output provided in the context.
  • Return a structured JSON findings object (schema described per-phase).
  • Suggest additional reconnaissance steps if coverage gaps exist.
  • Assign CVSS v3.1 base scores where applicable.
  • Set "exploitation_ready": true only after vulnerability_analysis is complete
    and at least one exploitable finding has been confirmed.

CRITICAL CONSTRAINT: You must NOT plan, suggest, or describe exploitation techniques.
Your role ends at vulnerability identification and prioritization. Flag findings as
"exploitation_ready" but provide no exploitation guidance. Exploitation is handled
exclusively by Claude API in the next phase.

Always output valid JSON unless explicitly asked for markdown prose.
"""

_CLAUDE_ORCHESTRATION_SYSTEM = """\
You are the exploitation and reporting engine of Aegis-360 AI, a professional \
penetration testing platform. You are invoked ONLY AFTER all pre-exploitation \
phases (recon, enumeration, vulnerability analysis) have been completed and \
validated by the orchestration gate.

YOUR RESPONSIBILITIES:
  1. EXPLOITATION — reason about and plan exploitation strategies for validated
     vulnerabilities. Generate precise exploitation execution plans, payload
     recommendations, and post-exploitation paths. Assess impact and business risk.
  2. REPORTING    — generate a comprehensive, client-ready penetration test report
     in Markdown format following the Aegis-360 report template.

CONSTRAINTS:
  • You do NOT perform reconnaissance or vulnerability scanning — that data is
    provided to you as structured input from the pre-exploitation phase.
  • You operate exclusively on validated, pre-collected findings.
  • For report generation, incorporate all findings from recon, enumeration,
    vulnerability analysis, and exploitation phases into the final report.

For exploitation tasks: return structured JSON with exploitation_plan, payloads,
expected_outcomes, impact_assessment, and post_exploitation_steps.

For report generation: return the complete Markdown report document exactly as
specified in the report template — no additional commentary, just the report.
"""

# ---------------------------------------------------------------------------
# DeepSeek V4 Pro Engine
# ---------------------------------------------------------------------------

class DeepSeekV4ProEngine:
    """
    Wraps OpenRouter API to provide DeepSeek V4 Pro intelligence.
    Exclusively handles RECON, ENUMERATION, and VULNERABILITY_ANALYSIS phases.
    """

    DEFAULT_MODEL = "deepseek/deepseek-v4-pro"

    def __init__(self):
        self._client: Optional[Any] = None
        self.enabled = False
        self.model_id = os.environ.get("DEEPSEEK_V4_PRO_MODEL", self.DEFAULT_MODEL)

        api_key = (
            os.environ.get("OPENROUTER_API_KEY") or
            os.environ.get("DEEPSEEK_V4_PRO_KEY") or
            os.environ.get("QWEN_API_KEY", "")
        )
        base_url = os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

        if not _OPENAI_SDK_OK:
            logger.warning("⚠️  DeepSeekV4ProEngine: openai SDK missing")
            return
        if not api_key:
            logger.warning("⚠️  DeepSeekV4ProEngine: no API key (set OPENROUTER_API_KEY)")
            return

        self._client = _OpenAI(api_key=api_key, base_url=base_url)
        self.enabled = True
        logger.info("✅ DeepSeekV4ProEngine: ready (model=%s)", self.model_id)

    def chat(self, user_prompt: str, phase: WorkflowPhase,
             max_tokens: int = 4096) -> str:
        """Send a phase-specific prompt; returns raw response text."""
        if not self.enabled or self._client is None:
            raise RuntimeError(
                "DeepSeekV4ProEngine not available — check OPENROUTER_API_KEY"
            )
        if phase not in DEEPSEEK_PHASES:
            raise PhaseViolationError(
                f"DeepSeek V4 Pro is not responsible for phase {phase.value}. "
                f"Allowed phases: {[p.value for p in DEEPSEEK_PHASES]}"
            )

        logger.info("🤖 [DeepSeek V4 Pro] Sending request | phase=%s | model=%s",
                    phase.value, self.model_id)
        try:
            resp = self._client.chat.completions.create(
                model=self.model_id,
                max_tokens=max_tokens,
                messages=[
                    {"role": "system", "content": _DEEPSEEK_SYSTEM},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            text = resp.choices[0].message.content
            logger.info("✅ [DeepSeek V4 Pro] Response received (%d chars) | phase=%s",
                        len(text), phase.value)
            return text
        except Exception as exc:
            logger.error("💥 [DeepSeek V4 Pro] Error: %s", exc)
            raise RuntimeError(f"DeepSeek V4 Pro call failed: {exc}") from exc

    def _parse_json(self, raw: str) -> dict:
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            import re
            m = re.search(r'\{[\s\S]+\}', raw)
            if m:
                try:
                    return json.loads(m.group())
                except json.JSONDecodeError:
                    pass
        return {"raw_response": raw}


# ---------------------------------------------------------------------------
# Claude Orchestration Engine
# ---------------------------------------------------------------------------

class ClaudeOrchestrationEngine:
    """
    Wraps the Anthropic SDK for exploitation planning and report generation.
    Must NOT be invoked during RECON, ENUMERATION, or VULNERABILITY_ANALYSIS.
    """

    MODEL = "claude-sonnet-4-6"

    def __init__(self):
        self._client: Optional[Any] = None
        self.enabled = False

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not _ANTHROPIC_SDK_OK:
            logger.warning("⚠️  ClaudeOrchestrationEngine: anthropic SDK missing")
            return
        if not api_key:
            logger.warning("⚠️  ClaudeOrchestrationEngine: ANTHROPIC_API_KEY not set")
            return

        self._client = _anthropic_sdk.Anthropic(api_key=api_key)
        self.enabled = True
        logger.info("✅ ClaudeOrchestrationEngine: ready (model=%s)", self.MODEL)

    def _guard_phase(self, current_phase: WorkflowPhase) -> None:
        """Hard enforcement: raise PhaseViolationError if called in a forbidden phase."""
        if current_phase in CLAUDE_FORBIDDEN_PHASES:
            raise PhaseViolationError(
                f"PHASE VIOLATION: Claude API must not be called during {current_phase.value}. "
                f"Claude API is restricted to EXPLOITATION and REPORTING phases. "
                f"Complete all pre-exploitation phases via DeepSeek V4 Pro first."
            )

    def chat(self, user_prompt: str, current_phase: WorkflowPhase,
             max_tokens: int = 8192) -> str:
        """Send a prompt to Claude API; enforces phase guard before every call."""
        self._guard_phase(current_phase)

        if not self.enabled or self._client is None:
            raise RuntimeError(
                "ClaudeOrchestrationEngine not available — check ANTHROPIC_API_KEY"
            )

        logger.info("🤖 [Claude API] Sending request | phase=%s | model=%s",
                    current_phase.value, self.MODEL)
        try:
            resp = self._client.messages.create(
                model=self.MODEL,
                max_tokens=max_tokens,
                system=[{
                    "type": "text",
                    "text": _CLAUDE_ORCHESTRATION_SYSTEM,
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": user_prompt}],
            )
            text = resp.content[0].text
            logger.info("✅ [Claude API] Response received (%d chars) | phase=%s",
                        len(text), current_phase.value)
            return text
        except _anthropic_sdk.AuthenticationError:
            raise RuntimeError("Claude API key invalid")
        except _anthropic_sdk.RateLimitError:
            raise RuntimeError("Claude API rate limit — retry later")
        except Exception as exc:
            logger.error("💥 [Claude API] Error: %s", exc)
            raise RuntimeError(f"Claude API call failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Workflow State
# ---------------------------------------------------------------------------

@dataclass
class WorkflowState:
    workflow_id: str
    target: str
    scope: str
    objective: str
    current_phase: WorkflowPhase = WorkflowPhase.START

    # Phase completion tracking
    phase_status: Dict[str, str] = field(default_factory=lambda: {
        p.value: PhaseStatus.PENDING.value for p in WorkflowPhase
    })

    # Assigned model per phase
    assigned_model: Dict[str, str] = field(default_factory=lambda: {
        WorkflowPhase.RECON.value:                  "claude-api",
        WorkflowPhase.ENUMERATION.value:            "claude-api",
        WorkflowPhase.VULNERABILITY_ANALYSIS.value: "claude-api",
        WorkflowPhase.EXPLOITATION.value:           "claude-api",
        WorkflowPhase.REPORTING.value:              "claude-api",
        WorkflowPhase.VALIDATION_GATE.value:        "orchestrator",
        WorkflowPhase.START.value:                  "orchestrator",
        WorkflowPhase.END.value:                    "orchestrator",
    })

    # Findings accumulated per phase
    findings: Dict[str, Any] = field(default_factory=dict)

    # Task history per phase
    task_history: Dict[str, List[Dict[str, Any]]] = field(default_factory=lambda: {
        p.value: [] for p in WorkflowPhase
    })

    # Gate & exploitation state
    exploitation_readiness: bool = False
    gate_check_result: Optional[Dict[str, Any]] = None
    exploitation_results: Optional[Dict[str, Any]] = None

    # Report
    report_path: Optional[str] = None
    report_filename: Optional[str] = None

    # Timestamps
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Handoff log — every model-to-model delegation is recorded here
    handoff_log: List[Dict[str, Any]] = field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id":          self.workflow_id,
            "target":               self.target,
            "scope":                self.scope,
            "objective":            self.objective,
            "current_phase":        self.current_phase.value,
            "phase_status":         self.phase_status,
            "assigned_model":       self.assigned_model,
            "findings":             self.findings,
            "task_history":         self.task_history,
            "exploitation_readiness": self.exploitation_readiness,
            "gate_check_result":    self.gate_check_result,
            "exploitation_results": self.exploitation_results,
            "report_path":          self.report_path,
            "report_filename":      self.report_filename,
            "created_at":           self.created_at,
            "updated_at":           self.updated_at,
            "handoff_log":          self.handoff_log,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WorkflowState":
        state = cls(
            workflow_id = d["workflow_id"],
            target      = d["target"],
            scope       = d.get("scope", ""),
            objective   = d.get("objective", ""),
        )
        state.current_phase        = WorkflowPhase(d["current_phase"])
        state.phase_status         = d.get("phase_status", state.phase_status)
        state.assigned_model       = d.get("assigned_model", state.assigned_model)
        state.findings             = d.get("findings", {})
        state.task_history         = d.get("task_history", state.task_history)
        state.exploitation_readiness = d.get("exploitation_readiness", False)
        state.gate_check_result    = d.get("gate_check_result")
        state.exploitation_results = d.get("exploitation_results")
        state.report_path          = d.get("report_path")
        state.report_filename      = d.get("report_filename")
        state.created_at           = d.get("created_at", state.created_at)
        state.updated_at           = d.get("updated_at", state.updated_at)
        state.handoff_log          = d.get("handoff_log", [])
        return state


# ---------------------------------------------------------------------------
# Report Template
# ---------------------------------------------------------------------------

_REPORT_PROMPT_TEMPLATE = """\
Generate a comprehensive, professional penetration testing report in Markdown format.
Use ONLY the findings provided below — do not invent or extrapolate data.
Follow the exact report structure specified. Return ONLY the Markdown document.

===== ASSESSMENT CONTEXT =====
Target: {target}
Scope: {scope}
Objective: {objective}
Assessment Date: {date}

===== RECON FINDINGS =====
{recon_findings}

===== ENUMERATION FINDINGS =====
{enum_findings}

===== VULNERABILITY ANALYSIS FINDINGS =====
{vuln_findings}

===== EXPLOITATION RESULTS =====
{exploit_results}

===== REQUIRED REPORT STRUCTURE =====

# Penetration Test Report

## Executive Summary

## Scope

## Methodology

### Reconnaissance
- Activities performed
- Tools used
- Key findings

### Enumeration
- Activities performed
- Tools used
- Key findings

### Vulnerability Analysis
- Vulnerabilities identified
- Risk ratings (Critical/High/Medium/Low/Informational)
- CVSS v3.1 scores where available
- Evidence

### Exploitation
- Exploitation attempts
- Successful exploitation results
- Impact assessment

## Findings

### Finding 1
- **Severity**: [Critical/High/Medium/Low/Informational]
- **CVSS Score**: [score if available]
- **Description**: ...
- **Evidence**: ...
- **Affected Assets**: ...
- **Risk**: ...
- **Remediation**: ...

[Continue for each finding...]

## Attack Path Summary

## Risk Matrix

## Remediation Recommendations

## Conclusion

## Appendix
- Commands executed
- Tool outputs
- References

===== INSTRUCTIONS =====
- Include CVSS v3.1 scores for all vulnerabilities where data is available.
- Assign severity ratings: Critical, High, Medium, Low, or Informational.
- Include proof-of-concept details and evidence for every finding.
- Provide specific, actionable remediation guidance for every finding.
- Make the executive summary suitable for a non-technical audience.
- The technical sections should be detailed enough for a developer to reproduce and fix issues.
- Return ONLY the Markdown report — no preamble, no commentary outside the document.
"""


# ---------------------------------------------------------------------------
# Model Orchestrator
# ---------------------------------------------------------------------------

class ModelOrchestrator:
    """
    Central coordinator for the Aegis-360 multi-model security assessment workflow.

    Responsibilities (Claude Code role):
      - Planning tasks and determining next workflow steps
      - Delegating to DeepSeek V4 Pro for pre-exploitation phases
      - Delegating to Claude API for exploitation and reporting
      - Enforcing phase gates (Claude API blocked until gate clears)
      - Maintaining structured JSON workflow state
      - Logging all model handoffs
    """

    def __init__(self):
        self._deepseek = DeepSeekV4ProEngine()
        self._claude   = ClaudeOrchestrationEngine()
        self._workflows: Dict[str, WorkflowState] = {}
        self._load_persisted_states()
        logger.info("✅ ModelOrchestrator: initialised | deepseek=%s | claude=%s",
                    self._deepseek.enabled, self._claude.enabled)

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _state_path(self, workflow_id: str) -> Path:
        return _STATE_DIR / f"{workflow_id}.json"

    def _save_state(self, wf: WorkflowState) -> None:
        wf.touch()
        try:
            with open(self._state_path(wf.workflow_id), "w") as fh:
                json.dump(wf.to_dict(), fh, indent=2)
        except OSError as exc:
            logger.warning("⚠️  Could not persist state for %s: %s", wf.workflow_id, exc)

    def _load_persisted_states(self) -> None:
        for fp in _STATE_DIR.glob("*.json"):
            try:
                with open(fp) as fh:
                    data = json.load(fh)
                wf = WorkflowState.from_dict(data)
                self._workflows[wf.workflow_id] = wf
            except Exception as exc:
                logger.warning("⚠️  Could not load state file %s: %s", fp, exc)
        logger.info("📂 Loaded %d persisted workflow(s)", len(self._workflows))

    def _get_workflow(self, workflow_id: str) -> WorkflowState:
        if workflow_id not in self._workflows:
            raise WorkflowNotFoundError(f"Workflow '{workflow_id}' not found")
        return self._workflows[workflow_id]

    # ------------------------------------------------------------------
    # Handoff logging
    # ------------------------------------------------------------------

    def _log_handoff(
        self,
        wf: WorkflowState,
        from_role: str,
        to_model: str,
        phase: WorkflowPhase,
        task_summary: str,
        decision_reason: str = "",
    ) -> None:
        entry = {
            "timestamp":     datetime.utcnow().isoformat(),
            "event":         "MODEL_HANDOFF",
            "workflow_id":   wf.workflow_id,
            "from_role":     MODEL_LABELS.get(from_role, from_role),
            "to_model":      MODEL_LABELS.get(to_model, to_model),
            "phase":         phase.value,
            "task_summary":  task_summary[:200],
            "decision_reason": decision_reason,
        }
        wf.handoff_log.append(entry)
        logger.info(
            "🔀 HANDOFF | %s → %s | phase=%s | task=%s",
            entry["from_role"], entry["to_model"], phase.value, task_summary[:80]
        )

    def _log_decision(
        self,
        wf: WorkflowState,
        decision: str,
        phase: WorkflowPhase,
        details: str = "",
    ) -> None:
        entry = {
            "timestamp":   datetime.utcnow().isoformat(),
            "event":       "ORCHESTRATOR_DECISION",
            "workflow_id": wf.workflow_id,
            "phase":       phase.value,
            "decision":    decision,
            "details":     details,
        }
        wf.handoff_log.append(entry)
        logger.info("🎯 DECISION | phase=%s | %s | %s", phase.value, decision, details)

    # ------------------------------------------------------------------
    # Workflow lifecycle
    # ------------------------------------------------------------------

    def start_workflow(self, target: str, scope: str = "",
                       objective: str = "Full penetration test") -> WorkflowState:
        """Create a new workflow and return its initial state."""
        wf_id = str(uuid.uuid4())
        wf = WorkflowState(
            workflow_id=wf_id,
            target=target,
            scope=scope,
            objective=objective,
        )
        wf.phase_status[WorkflowPhase.START.value] = PhaseStatus.COMPLETED.value
        self._log_decision(
            wf, "WORKFLOW_STARTED", WorkflowPhase.START,
            f"target={target} | objective={objective}"
        )
        self._workflows[wf_id] = wf
        self._save_state(wf)
        logger.info("🚀 Workflow started | id=%s | target=%s", wf_id, target)
        return wf

    def advance_phase(self, workflow_id: str) -> WorkflowState:
        """
        Advance the workflow to the next phase.
        Automatically runs the validation gate when transitioning out of
        VULNERABILITY_ANALYSIS. If the gate fails, raises PhaseGateError.
        """
        wf = self._get_workflow(workflow_id)
        current = wf.current_phase

        if current == WorkflowPhase.END:
            raise ValueError("Workflow has already completed (END state)")

        idx = PHASE_ORDER.index(current)
        next_phase = PHASE_ORDER[idx + 1]

        # Mark current phase completed before any gate check
        if current not in {WorkflowPhase.START, WorkflowPhase.END,
                           WorkflowPhase.VALIDATION_GATE}:
            wf.phase_status[current.value] = PhaseStatus.COMPLETED.value

        # When advancing to VALIDATION_GATE, run it automatically
        if next_phase == WorkflowPhase.VALIDATION_GATE:
            self._run_validation_gate(wf)
            # If gate passed, gate is set to COMPLETED and we skip to EXPLOITATION
            return wf

        wf.current_phase = next_phase
        wf.phase_status[next_phase.value] = PhaseStatus.IN_PROGRESS.value

        self._log_decision(
            wf, f"PHASE_ADVANCED: {current.value} → {next_phase.value}",
            next_phase,
            f"Assigned model: {MODEL_LABELS.get(wf.assigned_model.get(next_phase.value, ''), 'N/A')}"
        )
        self._save_state(wf)
        return wf

    def _run_validation_gate(self, wf: WorkflowState) -> None:
        """
        Check that all pre-exploitation phases are complete with findings.
        If passed: transition to EXPLOITATION.
        If failed: raise PhaseGateError.
        """
        missing = []
        warnings = []

        for phase in PRE_EXPLOITATION_PHASES:
            status = wf.phase_status.get(phase.value, PhaseStatus.PENDING.value)
            if status != PhaseStatus.COMPLETED.value:
                missing.append(f"{phase.value} (status: {status})")
            if not wf.findings.get(phase.value):
                warnings.append(f"{phase.value} has no findings recorded")

        gate_result = {
            "checked_at":    datetime.utcnow().isoformat(),
            "missing_phases": missing,
            "warnings":      warnings,
            "passed":        len(missing) == 0,
        }
        wf.gate_check_result = gate_result

        if missing:
            wf.phase_status[WorkflowPhase.VALIDATION_GATE.value] = PhaseStatus.FAILED.value
            self._log_decision(
                wf, "GATE_FAILED", WorkflowPhase.VALIDATION_GATE,
                f"Missing: {missing}"
            )
            self._save_state(wf)
            raise PhaseGateError(
                f"Validation gate FAILED. The following phases must be completed "
                f"before Claude API can be activated:\n"
                + "\n".join(f"  • {m}" for m in missing)
            )

        # Gate passed
        wf.exploitation_readiness = True
        wf.phase_status[WorkflowPhase.VALIDATION_GATE.value] = PhaseStatus.COMPLETED.value
        wf.current_phase = WorkflowPhase.EXPLOITATION
        wf.phase_status[WorkflowPhase.EXPLOITATION.value] = PhaseStatus.IN_PROGRESS.value

        self._log_decision(
            wf, "GATE_PASSED — Claude API activated for EXPLOITATION",
            WorkflowPhase.VALIDATION_GATE,
            f"Warnings: {warnings or 'none'}"
        )
        self._log_handoff(
            wf,
            from_role="orchestrator",
            to_model="claude-api",
            phase=WorkflowPhase.EXPLOITATION,
            task_summary="All pre-exploitation phases validated. Handing off to Claude API.",
            decision_reason="Validation gate cleared — all pre-exploitation phases complete.",
        )
        self._save_state(wf)

    # ------------------------------------------------------------------
    # Task dispatch
    # ------------------------------------------------------------------

    def submit_task(
        self,
        workflow_id: str,
        task: str,
        tool_outputs: str = "",
        max_tokens: int = 4096,
    ) -> Dict[str, Any]:
        """
        Submit a task to the model responsible for the current phase.
        Enforces model assignments — wrong-phase calls are rejected.
        """
        wf = self._get_workflow(workflow_id)
        phase = wf.current_phase

        if phase in CLAUDE_PHASES:
            return self._dispatch_to_claude(wf, phase, task, tool_outputs, max_tokens)
        else:
            raise ValueError(
                f"Phase {phase.value} does not accept model tasks. "
                f"Use /api/orchestration/advance to move through START and VALIDATION_GATE."
            )

    def _build_deepseek_prompt(
        self,
        wf: WorkflowState,
        phase: WorkflowPhase,
        task: str,
        tool_outputs: str,
    ) -> str:
        phase_context = {
            WorkflowPhase.RECON: (
                "PHASE: RECONNAISSANCE\n"
                "Focus: passive/active recon, OSINT, subdomain discovery, port scanning strategy, "
                "technology fingerprinting, service detection.\n"
                "Return JSON: {phase, target, tools_recommended: [{tool, command, flags, purpose}], "
                "findings: {subdomains, open_ports, technologies, services, notes}, "
                "additional_recon_steps, exploitation_ready: false}"
            ),
            WorkflowPhase.ENUMERATION: (
                "PHASE: ENUMERATION\n"
                "Focus: deep service enumeration, directory/file discovery, endpoint mapping, "
                "parameter analysis, authentication surface, API discovery.\n"
                "Return JSON: {phase, target, tools_recommended: [{tool, command, flags, purpose}], "
                "findings: {directories, endpoints, parameters, auth_endpoints, api_routes, "
                "interesting_files, services_detailed}, additional_steps, exploitation_ready: false}"
            ),
            WorkflowPhase.VULNERABILITY_ANALYSIS: (
                "PHASE: VULNERABILITY ANALYSIS\n"
                "Focus: triage all collected findings, assign CVSS v3.1 scores, assess "
                "exploitability, prioritize by risk. Generate exploitation recommendations "
                "(without providing exploitation details).\n"
                "Return JSON: {phase, target, vulnerabilities: [{id, name, severity, cvss_score, "
                "cvss_vector, affected_asset, description, evidence, exploitability, "
                "remediation, exploitation_recommendation}], "
                "risk_summary: {critical, high, medium, low, informational}, "
                "attack_surface_summary, exploitation_ready: bool}"
            ),
        }

        ctx_header = phase_context.get(phase, f"PHASE: {phase.value}")
        prior_ctx = ""
        for prior_phase in PRE_EXPLOITATION_PHASES:
            if prior_phase.value in wf.findings and prior_phase != phase:
                prior_ctx += f"\n--- Prior {prior_phase.value} findings ---\n"
                prior_ctx += json.dumps(wf.findings[prior_phase.value], indent=2)[:2000]
                prior_ctx += "\n"

        prompt = (
            f"{ctx_header}\n\n"
            f"TARGET: {wf.target}\n"
            f"SCOPE: {wf.scope}\n"
            f"OBJECTIVE: {wf.objective}\n\n"
            f"TASK: {task}\n"
        )
        if tool_outputs:
            prompt += f"\nTOOL OUTPUTS PROVIDED:\n{tool_outputs}\n"
        if prior_ctx:
            prompt += f"\nPRIOR PHASE CONTEXT:{prior_ctx}"

        return prompt

    def _dispatch_to_deepseek(
        self,
        wf: WorkflowState,
        phase: WorkflowPhase,
        task: str,
        tool_outputs: str,
        max_tokens: int,
    ) -> Dict[str, Any]:
        self._log_handoff(
            wf, "orchestrator", "deepseek-v4-pro", phase,
            task_summary=task[:150],
            decision_reason=f"Phase {phase.value} is exclusively handled by DeepSeek V4 Pro.",
        )

        prompt = self._build_deepseek_prompt(wf, phase, task, tool_outputs)
        raw = self._deepseek.chat(prompt, phase, max_tokens)
        findings = self._deepseek._parse_json(raw)

        # Accumulate findings
        if phase.value not in wf.findings:
            wf.findings[phase.value] = {}
        wf.findings[phase.value].update(findings)

        # Record task in history
        wf.task_history[phase.value].append({
            "timestamp": datetime.utcnow().isoformat(),
            "task":      task[:200],
            "model":     "deepseek-v4-pro",
            "model_id":  self._deepseek.model_id,
            "response_chars": len(raw),
        })

        # Check exploitation readiness from analysis phase
        if phase == WorkflowPhase.VULNERABILITY_ANALYSIS:
            if findings.get("exploitation_ready"):
                wf.exploitation_readiness = True
                self._log_decision(
                    wf, "EXPLOITATION_READY_FLAGGED",
                    phase,
                    "DeepSeek V4 Pro flagged exploitation_ready=true"
                )

        self._save_state(wf)

        return {
            "workflow_id":    wf.workflow_id,
            "phase":          phase.value,
            "model":          "deepseek-v4-pro",
            "model_id":       self._deepseek.model_id,
            "provider":       "OpenRouter",
            "findings":       findings,
            "raw_response":   raw,
            "task":           task[:200],
            "timestamp":      datetime.utcnow().isoformat(),
        }

    def _dispatch_to_claude(
        self,
        wf: WorkflowState,
        phase: WorkflowPhase,
        task: str,
        tool_outputs: str,
        max_tokens: int,
    ) -> Dict[str, Any]:
        # Hard phase guard — raises PhaseViolationError if phase is forbidden
        if phase in CLAUDE_FORBIDDEN_PHASES:
            raise PhaseViolationError(
                f"BLOCKED: Claude API cannot be called during {phase.value}. "
                "Pre-exploitation phases must be completed by DeepSeek V4 Pro."
            )

        if not wf.exploitation_readiness and phase == WorkflowPhase.EXPLOITATION:
            raise PhaseGateError(
                "Exploitation phase requires the validation gate to have passed. "
                "Call /api/orchestration/advance to run the gate check."
            )

        self._log_handoff(
            wf, "orchestrator", "claude-api", phase,
            task_summary=task[:150],
            decision_reason=(
                "Gate validated. All pre-exploitation phases complete. "
                f"Phase {phase.value} is exclusively handled by Claude API."
            ),
        )

        prior_findings = json.dumps(wf.findings, indent=2)[:6000]
        prompt = (
            f"PHASE: {phase.value}\n"
            f"TARGET: {wf.target}\n"
            f"SCOPE: {wf.scope}\n"
            f"OBJECTIVE: {wf.objective}\n\n"
            f"ALL PRE-EXPLOITATION FINDINGS:\n{prior_findings}\n\n"
            f"CURRENT TASK: {task}\n"
        )
        if tool_outputs:
            prompt += f"\nADDITIONAL CONTEXT:\n{tool_outputs}\n"

        raw = self._claude.chat(prompt, phase, max_tokens)
        result = self._deepseek._parse_json(raw)  # reuse parser

        # Store exploitation results
        if phase == WorkflowPhase.EXPLOITATION:
            wf.exploitation_results = result
            wf.phase_status[WorkflowPhase.EXPLOITATION.value] = PhaseStatus.COMPLETED.value

        wf.task_history[phase.value].append({
            "timestamp":      datetime.utcnow().isoformat(),
            "task":           task[:200],
            "model":          "claude-api",
            "model_id":       ClaudeOrchestrationEngine.MODEL,
            "response_chars": len(raw),
        })

        if phase.value not in wf.findings:
            wf.findings[phase.value] = {}
        wf.findings[phase.value].update(result)

        self._save_state(wf)

        return {
            "workflow_id":   wf.workflow_id,
            "phase":         phase.value,
            "model":         "claude-api",
            "model_id":      ClaudeOrchestrationEngine.MODEL,
            "provider":      "Anthropic",
            "result":        result,
            "raw_response":  raw,
            "task":          task[:200],
            "timestamp":     datetime.utcnow().isoformat(),
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        workflow_id: str,
        filename: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Invoke Claude API to generate the final penetration test report.
        Only callable once the workflow has reached REPORTING phase.
        Saves the report to pentest_reports/ and returns the content.
        """
        wf = self._get_workflow(workflow_id)

        if wf.current_phase not in {WorkflowPhase.REPORTING, WorkflowPhase.END}:
            # Auto-advance to REPORTING if EXPLOITATION is done
            if wf.phase_status.get(WorkflowPhase.EXPLOITATION.value) == PhaseStatus.COMPLETED.value:
                wf.current_phase = WorkflowPhase.REPORTING
                wf.phase_status[WorkflowPhase.REPORTING.value] = PhaseStatus.IN_PROGRESS.value
                self._save_state(wf)
            else:
                raise ValueError(
                    f"Report generation requires REPORTING phase. "
                    f"Current phase: {wf.current_phase.value}. "
                    f"Complete the EXPLOITATION phase first."
                )

        self._log_handoff(
            wf, "orchestrator", "claude-api", WorkflowPhase.REPORTING,
            task_summary="Generate final penetration test report (Markdown)",
            decision_reason="All assessment phases complete. Claude API generating consolidated report.",
        )

        def _fmt(data: Any) -> str:
            if not data:
                return "No data recorded for this phase."
            return json.dumps(data, indent=2)[:4000]

        prompt = _REPORT_PROMPT_TEMPLATE.format(
            target          = wf.target,
            scope           = wf.scope or "As defined in engagement contract",
            objective       = wf.objective,
            date            = datetime.utcnow().strftime("%Y-%m-%d"),
            recon_findings  = _fmt(wf.findings.get(WorkflowPhase.RECON.value)),
            enum_findings   = _fmt(wf.findings.get(WorkflowPhase.ENUMERATION.value)),
            vuln_findings   = _fmt(wf.findings.get(WorkflowPhase.VULNERABILITY_ANALYSIS.value)),
            exploit_results = _fmt(wf.exploitation_results),
        )

        report_md = self._claude.chat(prompt, WorkflowPhase.REPORTING, max_tokens=8192)

        # Save to disk
        safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in wf.target)
        fname = filename or f"pentest-report-{safe_target}-{wf.workflow_id[:8]}.md"
        report_path = _REPORT_DIR / fname
        report_path.write_text(report_md, encoding="utf-8")

        wf.report_path     = str(report_path)
        wf.report_filename = fname
        wf.phase_status[WorkflowPhase.REPORTING.value] = PhaseStatus.COMPLETED.value
        wf.current_phase   = WorkflowPhase.END
        wf.phase_status[WorkflowPhase.END.value] = PhaseStatus.COMPLETED.value

        self._log_decision(
            wf, "REPORT_GENERATED", WorkflowPhase.REPORTING,
            f"Saved to {report_path}"
        )
        self._save_state(wf)

        logger.info("📄 Report generated | workflow=%s | path=%s", workflow_id, report_path)
        return {
            "workflow_id":    workflow_id,
            "report_path":    str(report_path),
            "report_filename": fname,
            "report_content": report_md,
            "phase":          WorkflowPhase.REPORTING.value,
            "timestamp":      datetime.utcnow().isoformat(),
        }


# ---------------------------------------------------------------------------
# Singleton orchestrator instance
# ---------------------------------------------------------------------------
orchestrator = ModelOrchestrator()


# ---------------------------------------------------------------------------
# Flask Blueprint
# ---------------------------------------------------------------------------
orchestrator_bp = Blueprint("orchestration", __name__, url_prefix="/api/orchestration")


def _err(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg}), code


# ── POST /api/orchestration/start ──────────────────────────────────────────
@orchestrator_bp.route("/start", methods=["POST"])
def start_workflow():
    """
    Start a new multi-model security assessment workflow.

    Body: {
      "target":    "example.com",          (required)
      "scope":     "*.example.com",        (optional)
      "objective": "Full penetration test" (optional)
    }

    Returns the initial WorkflowState as JSON.
    """
    p = request.json or {}
    target = p.get("target", "").strip()
    if not target:
        return _err("'target' is required")

    wf = orchestrator.start_workflow(
        target    = target,
        scope     = p.get("scope", ""),
        objective = p.get("objective", "Full penetration test"),
    )
    return jsonify({
        "success":     True,
        "message":     f"Workflow started. Advance to RECON and submit tasks to DeepSeek V4 Pro.",
        "next_action": "POST /api/orchestration/advance to begin RECON phase",
        "state":       wf.to_dict(),
    })


# ── GET /api/orchestration/state/<workflow_id> ─────────────────────────────
@orchestrator_bp.route("/state/<workflow_id>", methods=["GET"])
def get_state(workflow_id: str):
    """Return the current WorkflowState for a given workflow_id."""
    try:
        wf = orchestrator._get_workflow(workflow_id)
        return jsonify({"success": True, "state": wf.to_dict()})
    except WorkflowNotFoundError as exc:
        return _err(str(exc), 404)


# ── GET /api/orchestration/workflows ──────────────────────────────────────
@orchestrator_bp.route("/workflows", methods=["GET"])
def list_workflows():
    """List all workflows with summary information."""
    summaries = []
    for wf in orchestrator._workflows.values():
        summaries.append({
            "workflow_id":    wf.workflow_id,
            "target":         wf.target,
            "current_phase":  wf.current_phase.value,
            "exploitation_readiness": wf.exploitation_readiness,
            "report_path":    wf.report_path,
            "created_at":     wf.created_at,
            "updated_at":     wf.updated_at,
        })
    summaries.sort(key=lambda x: x["updated_at"], reverse=True)
    return jsonify({"success": True, "workflows": summaries, "count": len(summaries)})


# ── POST /api/orchestration/advance ───────────────────────────────────────
@orchestrator_bp.route("/advance", methods=["POST"])
def advance_phase():
    """
    Advance the workflow to the next phase.

    When advancing from VULNERABILITY_ANALYSIS, the validation gate runs
    automatically. If the gate fails, a 403 is returned with the missing phases.

    Body: {"workflow_id": "<id>"}
    """
    p = request.json or {}
    wf_id = p.get("workflow_id", "").strip()
    if not wf_id:
        return _err("'workflow_id' is required")

    try:
        wf = orchestrator.advance_phase(wf_id)
        assigned = wf.assigned_model.get(wf.current_phase.value, "orchestrator")
        return jsonify({
            "success":      True,
            "current_phase": wf.current_phase.value,
            "assigned_model": MODEL_LABELS.get(assigned, assigned),
            "exploitation_readiness": wf.exploitation_readiness,
            "message": (
                f"Workflow advanced to {wf.current_phase.value}. "
                f"Assigned model: {MODEL_LABELS.get(assigned, assigned)}"
            ),
            "state": wf.to_dict(),
        })
    except PhaseGateError as exc:
        return jsonify({
            "success":   False,
            "error":     "VALIDATION_GATE_FAILED",
            "detail":    str(exc),
            "gate_result": orchestrator._get_workflow(wf_id).gate_check_result,
        }), 403
    except WorkflowNotFoundError as exc:
        return _err(str(exc), 404)
    except ValueError as exc:
        return _err(str(exc))


# ── POST /api/orchestration/task ──────────────────────────────────────────
@orchestrator_bp.route("/task", methods=["POST"])
def submit_task():
    """
    Submit a task to the model responsible for the current workflow phase.

    Routing is automatic and enforced:
      RECON / ENUMERATION / VULNERABILITY_ANALYSIS → DeepSeek V4 Pro
      EXPLOITATION / REPORTING                     → Claude API (gate must be clear)

    Body: {
      "workflow_id":   "<id>",                         (required)
      "task":          "Analyze nmap output for ...",  (required)
      "tool_outputs":  "<raw scan output>",            (optional)
      "max_tokens":    4096                            (optional)
    }
    """
    p = request.json or {}
    wf_id = p.get("workflow_id", "").strip()
    task  = p.get("task", "").strip()

    if not wf_id:
        return _err("'workflow_id' is required")
    if not task:
        return _err("'task' is required")

    try:
        result = orchestrator.submit_task(
            workflow_id  = wf_id,
            task         = task,
            tool_outputs = p.get("tool_outputs", ""),
            max_tokens   = int(p.get("max_tokens", 4096)),
        )
        return jsonify({"success": True, **result})
    except PhaseViolationError as exc:
        return jsonify({"success": False, "error": "PHASE_VIOLATION", "detail": str(exc)}), 403
    except PhaseGateError as exc:
        return jsonify({"success": False, "error": "GATE_NOT_CLEARED", "detail": str(exc)}), 403
    except WorkflowNotFoundError as exc:
        return _err(str(exc), 404)
    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 503
    except Exception as exc:
        logger.exception("Unexpected error in submit_task")
        return _err(str(exc), 500)


# ── POST /api/orchestration/report ────────────────────────────────────────
@orchestrator_bp.route("/report", methods=["POST"])
def generate_report():
    """
    Generate the final penetration test report via Claude API.
    Only available after the EXPLOITATION phase is complete.
    Saves the report as Markdown to pentest_reports/.

    Body: {
      "workflow_id":       "<id>",               (required)
      "report_filename":   "pentest-report.md"   (optional)
    }
    """
    p = request.json or {}
    wf_id    = p.get("workflow_id", "").strip()
    filename = p.get("report_filename", "").strip() or None

    if not wf_id:
        return _err("'workflow_id' is required")

    try:
        result = orchestrator.generate_report(wf_id, filename)
        return jsonify({"success": True, **result})
    except PhaseViolationError as exc:
        return jsonify({"success": False, "error": "PHASE_VIOLATION", "detail": str(exc)}), 403
    except ValueError as exc:
        return _err(str(exc))
    except WorkflowNotFoundError as exc:
        return _err(str(exc), 404)
    except RuntimeError as exc:
        return jsonify({"success": False, "error": str(exc)}), 503
    except Exception as exc:
        logger.exception("Unexpected error in generate_report")
        return _err(str(exc), 500)


# ── GET /api/orchestration/handoffs/<workflow_id> ─────────────────────────
@orchestrator_bp.route("/handoffs/<workflow_id>", methods=["GET"])
def get_handoffs(workflow_id: str):
    """
    Return the full model handoff and decision log for a workflow.
    Useful for auditing the orchestration chain.
    """
    try:
        wf = orchestrator._get_workflow(workflow_id)
        return jsonify({
            "success":     True,
            "workflow_id": workflow_id,
            "target":      wf.target,
            "handoff_log": wf.handoff_log,
            "count":       len(wf.handoff_log),
        })
    except WorkflowNotFoundError as exc:
        return _err(str(exc), 404)


# ── GET /api/orchestration/status ─────────────────────────────────────────
@orchestrator_bp.route("/status", methods=["GET"])
def orchestration_status():
    """Health check and model availability status."""
    return jsonify({
        "success":   True,
        "service":   "Aegis-360 Multi-Model Orchestration Engine",
        "models": {
            "claude_api": {
                "enabled":  orchestrator._claude.enabled,
                "model_id": ClaudeOrchestrationEngine.MODEL,
                "provider": "Anthropic",
                "phases":   [p.value for p in CLAUDE_PHASES],
            },
        },
        "phase_order":       [p.value for p in PHASE_ORDER],
        "active_workflows":  len(orchestrator._workflows),
        "state_dir":         str(_STATE_DIR),
        "report_dir":        str(_REPORT_DIR),
        "workflow_endpoints": {
            "start":    "POST /api/orchestration/start",
            "advance":  "POST /api/orchestration/advance",
            "task":     "POST /api/orchestration/task",
            "report":   "POST /api/orchestration/report",
            "state":    "GET  /api/orchestration/state/<workflow_id>",
            "handoffs": "GET  /api/orchestration/handoffs/<workflow_id>",
            "list":     "GET  /api/orchestration/workflows",
        },
    })
