# Standards and Framework Mapping — Red-Teaming LLMs with DeepTeam

## MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

| ID | Name | Relevance |
|----|------|-----------|
| AML.T0051 | LLM Prompt Injection | PromptInjection, EmbeddedInstructionJSON, SyntheticContextInjection, and IndirectInstruction attacks craft inputs that subvert the model's intended instructions; the evaluation model scores whether the model obeyed the injection. |
| AML.T0054 | LLM Jailbreak | LinearJailbreaking, TreeJailbreaking, CrescendoJailbreaking, and BadLikertJudge drive the model past safety guardrails over one or more turns; scored pass/fail per turn sequence. |
| AML.T0057 | LLM Data Leakage | PIILeakage, PromptLeakage, and SystemReconnaissance probe whether the model discloses PII, system prompt content, file metadata, or database schema in its responses. |

Reference: https://atlas.mitre.org/

## NIST AI Risk Management Framework (AI RMF 1.0)

| ID | Function / Subcategory | Relevance |
|----|------------------------|-----------|
| MEASURE-2.7 | AI system security and resilience are evaluated and documented | DeepTeam produces repeatable, scored assessments across 34 vulnerability categories; results provide quantitative evidence for this subcategory in an AI risk assessment or model card. |
| GOVERN-1.2 | Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place | Systematic red-teaming output supports governance evidence of proactive risk identification. |

Reference: https://www.nist.gov/itl/ai-risk-management-framework

## OWASP Top 10 for LLM Applications 2025

| OWASP ID | Risk | DeepTeam Vulnerabilities |
|----------|------|--------------------------|
| LLM01:2025 | Prompt Injection | PromptLeakage, IndirectInstruction, SyntheticContextInjection (attacks: PromptInjection, EmbeddedInstructionJSON) |
| LLM02:2025 | Sensitive Information Disclosure | PIILeakage, PromptLeakage, SystemReconnaissance |
| LLM03:2025 | Supply Chain Vulnerabilities | ToolMetadataPoisoning, CrossContextRetrieval |
| LLM04:2025 | Data and Model Poisoning | Hallucination, Misinformation |
| LLM05:2025 | Improper Output Handling | SQLInjection, ShellInjection, UnexpectedCodeExecution, SSRF |
| LLM06:2025 | Excessive Agency | ExcessiveAgency, ToolOrchestrationAbuse, ExternalSystemAbuse |
| LLM07:2025 | System Prompt Leakage | PromptLeakage |
| LLM08:2025 | Vector and Embedding Weaknesses | CrossContextRetrieval, IndirectInstruction |
| LLM09:2025 | Misinformation | Misinformation, Hallucination |
| LLM10:2025 | Unbounded Consumption | (use scan rate-limiting and max_concurrent controls) |

Reference: https://genai.owasp.org/

## DeepTeam Vulnerability → Attack Mapping

| Vulnerability | Recommended Attacks | Rationale |
|--------------|---------------------|-----------|
| Toxicity | Roleplay, MathProblem, EmotionalManipulation | Indirect framing elicits harmful content |
| PIILeakage | Roleplay, AuthorityEscalation, SyntheticContextInjection | Social engineering to extract user data |
| PromptLeakage | PromptProbing, GrayBox, SystemOverride | Direct and indirect system prompt extraction |
| SQLInjection | PromptInjection, EmbeddedInstructionJSON | Craft SQL payloads within natural language |
| SSRF | SystemOverride, GoalRedirection | Make the agent issue internal network requests |
| ShellInjection | PermissionEscalation, AuthorityEscalation | Escalate to shell command execution |
| ExcessiveAgency | GoalRedirection, ContextFlooding | Override agent's original goal/scope |
| RBAC | PermissionEscalation, AuthorityEscalation | Claim elevated permissions or roles |
| IndirectInstruction | SyntheticContextInjection, ContextPoisoning | Embed instructions in retrieved external content |
| Jailbreak (all) | LinearJailbreaking, CrescendoJailbreaking, TreeJailbreaking | Multi-turn escalation for safety bypass |

## ISO/IEC 42001:2023 (AI Management System)

| Clause | Relevance |
|--------|-----------|
| 6.1 — Actions to address risks and opportunities | Red-team results feed directly into the risk register for AI systems |
| 9.1 — Monitoring, measurement, analysis and evaluation | Scored DeepTeam runs provide repeatable measurement artifacts |
| 10.1 — Continual improvement | Pre/post guardrail comparisons demonstrate improvement with evidence |
