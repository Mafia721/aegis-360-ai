# Graph Report - .  (2026-07-21)

## Corpus Check
- Large corpus: 3822 files · ~2,699,467 words. Semantic extraction will be expensive (many Claude tokens). Consider running on a subfolder.

## Summary
- 1228 nodes · 2348 edges · 151 communities (53 shown, 98 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 14 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- Model Orchestration & Workflow
- AI Exploit Generation
- Agent Runtime & Model Providers
- Command Execution Engine
- Tool API Endpoints
- Target Profiling & Optimization
- Server Core & Tool Registry
- Error Recovery & Resilience
- File & Payload Operations
- Browser Agent & Web Recon
- CVE Intelligence & Exploit Search
- Bug Bounty Automation
- Graceful Degradation & Fallbacks
- AI Payload Generation
- Visual Engine & Dashboard
- Target Analysis & Attack Surface
- Caching Layer
- HTTP Testing Framework
- CTF Workflow Automation
- Process Pool & Scaling
- Qwen AI Engine
- Chat REPL & Model Routing
- MCP Client & Health
- MCP Server Logging
- Parameter & Performance Optimization
- Attack Chain Builder
- Burp Suite & Browser Integration
- CTF Challenge Automation
- Error Classification
- File Operations Management
- Decision Engine
- Resource Monitoring
- Telemetry & Health
- CTF Team Coordination
- Failure Recovery & Tech Detection
- Project Documentation
- CTF Challenge Model
- Claude AI Engine
- Async Process Management
- Attack Chain Steps
- CTFToolManager
- install.sh
- Aegis360Cache
- .chat()
- .get_comprehensive_stats()
- qwen_full_pipeline()
- FileUploadTestingFramework
- PerformanceDashboard
- RateLimitDetector
- .format_tool_status()
- upload_to_github.sh
- ColoredFormatter
- ai_test_payload()
- angr()
- api_fuzzer()
- api_schema_analyzer()
- arjun()
- autorecon()
- checkov()
- clair()
- cloudmapper()
- dalfox()
- dirb()
- dirsearch()
- dnsenum()
- docker_bench_security()
- enum4linux()
- enum4linux_ng()
- execute_amass_scan()
- execute_arjun_scan()
- execute_dalfox_scan()
- execute_feroxbuster_scan()
- execute_ffuf_scan()
- execute_gobuster_scan()
- execute_httpx_scan()
- execute_nikto_scan()
- execute_nmap_scan()
- execute_nuclei_scan()
- execute_paramspider_scan()
- execute_sqlmap_scan()
- execute_subfinder_scan()
- execute_wpscan_scan()
- falco()
- feroxbuster()
- ffuf()
- fierce()
- gdb()
- ghidra()
- gobuster()
- graphify_benchmark()
- graphify_build()
- graphify_query()
- graphify_update()
- graphql_scanner()
- hakrawler()
- hashpump()
- hydra()
- ._optimize_checkov_params()
- ._optimize_kube_hunter_params()
- ._optimize_nuclei_params()
- ._optimize_scout_suite_params()
- ._optimize_trivy_params()
- jaeles()
- john()
- jwt_analyzer()
- katana()
- kube_bench()
- kube_hunter()
- metasploit()
- msfvenom()
- netexec()
- nikto()
- nmap()
- nmap_advanced()
- nuclei()
- objdump()
- one_gadget()
- pacu()
- pwninit()
- pwntools()
- qwen_aggregate_for_claude()
- qwen_analyze_code()
- qwen_crawl_and_parse()
- qwen_generate_poc()
- qwen_generate_shellcode()
- qwen_write_exploit()
- qwen_write_tool()
- radare2()
- trivy()
- terrascan()
- sqlmap()
- wpscan()
- subfinder()
- rustscan()
- rpcclient()
- volatility()
- ropgadget()
- xxd()
- strings()
- ropper()
- xsser()
- wfuzz()
- waybackurls()
- x8()
- uro()
- zap()
- wafw00f()
- volatility3()
- steghide()
- install_sudo_tools.sh

## God Nodes (most connected - your core abstractions)
1. `execute_command()` - 125 edges
2. `IntelligentDecisionEngine` - 39 edges
3. `TargetProfile` - 33 edges
4. `AIExploitGenerator` - 21 edges
5. `execute_command_with_recovery()` - 21 edges
6. `BrowserAgent` - 20 edges
7. `CTFChallenge` - 19 edges
8. `ModelOrchestrator` - 17 edges
9. `IntelligentErrorHandler` - 17 edges
10. `QwenAIEngine` - 15 edges

## Surprising Connections (you probably didn't know these)
- `Claude Sonnet 4.6 — Exploitation and Reporting AI Model` --conceptually_related_to--> `Anthropic Python SDK (Claude API)`  [INFERRED]
  CAPABILITIES.md → requirements.txt
- `.env-Based API Keys / Secrets Management` --conceptually_related_to--> `Anthropic Python SDK (Claude API)`  [INFERRED]
  INSTALL.md → requirements.txt
- `Phased Pentest Workflow Engine with Model Separation` --conceptually_related_to--> `Smart AI Model Routing (task-to-model assignment logic)`  [INFERRED]
  CHANGELOG.md → CAPABILITIES.md
- `Contributing Guide for aegis-360-ai` --references--> `Aegis-360 AI Capabilities Reference`  [EXTRACTED]
  CONTRIBUTING.md → CAPABILITIES.md
- `Aegis-360 AI README` --references--> `Aegis-360 AI Capabilities Reference`  [EXTRACTED]
  README.md → CAPABILITIES.md

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Two-Component MCP+Flask Architecture: Claude Desktop connects via aegis_360_mcp to aegis_360_server** — aegis_360_mcp, aegis_360_server, mcp_protocol [EXTRACTED 1.00]
- **Phased Model Separation: Orchestrator enforces DeepSeek for recon phases, Claude for exploitation/reporting** — aegis_360_orchestrator, deepseek_v4_pro, claude_sonnet, phased_workflow [EXTRACTED 1.00]
- **Core Pentest Framework: Flask server + MCP bridge + orchestrator + CLI form the full execution stack** — aegis_360_server, aegis_360_mcp, aegis_360_orchestrator, aegis360chat [EXTRACTED 1.00]

## Communities (151 total, 98 thin omitted)

### Community 0 - "Model Orchestration & Workflow"
Cohesion: 0.05
Nodes (55): advance_phase(), ClaudeOrchestrationEngine, DeepSeekV4ProEngine, _err(), generate_report(), get_handoffs(), get_state(), list_workflows() (+47 more)

### Community 1 - "AI Exploit Generation"
Cohesion: 0.05
Nodes (27): AIExploitGenerator, discover_attack_chains(), Discover multi-stage attack possibilities, AI-powered exploit development and enhancement system, Generate working exploit from real CVE data with specific implementation, Classify vulnerability type from description, Select appropriate exploit template, Generate parameters for exploit template (+19 more)

### Community 2 - "Agent Runtime & Model Providers"
Cohesion: 0.06
Nodes (33): agent_run(), AgentRunner, _call_model(), ctf_binary_analyzer(), ctf_forensics_analyzer(), foremost(), _get_model_client(), install_python_package() (+25 more)

### Community 3 - "Command Execution Engine"
Cohesion: 0.05
Nodes (27): EnhancedCommandExecutor, get_process_status(), list_processes(), pause_process(), ProcessManager, Enhanced process manager for command termination and monitoring, Register a new active process, Update process progress and stats (+19 more)

### Community 4 - "Tool API Endpoints"
Cohesion: 0.05
Nodes (38): anew(), apiharvester(), arp_scan(), binwalk(), dotdotpwn(), electronegativity(), execute_command(), execute_dirsearch_scan() (+30 more)

### Community 5 - "Target Profiling & Optimization"
Cohesion: 0.08
Nodes (19): Select optimal tools based on target profile and objective, Enhanced parameter optimization with advanced intelligence, Optimize Nmap parameters, Optimize Gobuster parameters, Optimize SQLMap parameters, Optimize FFuf parameters, Optimize Hydra parameters, Optimize Rustscan parameters (+11 more)

### Community 6 - "Server Core & Tool Registry"
Cohesion: 0.07
Nodes (32): agent_tools(), amass(), checksec(), create_vulnerability_card(), generic_command(), get_error_statistics(), graphify_explain(), httpx() (+24 more)

### Community 7 - "Error Recovery & Resilience"
Cohesion: 0.09
Nodes (23): classify_error_endpoint(), _determine_operation_type(), ErrorContext, execute_command_with_recovery(), execute_with_recovery_endpoint(), Context information for error handling decisions, Recovery strategy with configuration, Test error recovery system with simulated failures (+15 more)

### Community 8 - "File & Payload Operations"
Cohesion: 0.08
Nodes (28): chat_models(), configure_auto_scaling(), create_file(), ctf_cryptography_solver(), delete_file(), execute_command_async(), execute_python_script(), format_tool_output() (+20 more)

### Community 9 - "Browser Agent & Web Recon"
Cohesion: 0.11
Nodes (12): BrowserAgent, AI-powered browser agent for web application testing and inspection, Navigate to URL and perform comprehensive inspection, Collect console errors & warnings (if supported), Extract local storage data, Extract session storage data, Extract all forms from the page, Extract all links from the page (+4 more)

### Community 10 - "CVE Intelligence & Exploit Search"
Cohesion: 0.08
Nodes (17): cve_monitor(), CVEIntelligenceManager, exploit_generate(), Monitor CVE databases for new vulnerabilities with AI analysis, Generate exploits from vulnerability data using AI, Aggregate and correlate threat intelligence from multiple sources, Create the enhanced Aegis360 banner, Advanced CVE Intelligence and Vulnerability Management System (+9 more)

### Community 11 - "Bug Bounty Automation"
Cohesion: 0.11
Nodes (19): BugBountyTarget, BugBountyWorkflowManager, create_business_logic_workflow(), create_comprehensive_bugbounty_assessment(), create_osint_workflow(), create_reconnaissance_workflow(), create_vulnerability_hunting_workflow(), Create comprehensive reconnaissance workflow for bug bounty hunting (+11 more)

### Community 12 - "Graceful Degradation & Fallbacks"
Cohesion: 0.11
Nodes (13): get_fallback_chains(), GracefulDegradation, Get available fallback tool chains, Ensure system continues operating even with partial tool failures, Initialize fallback tool chains for critical operations, Initialize set of critical operations that must not fail completely, Create fallback tool chain for critical operations, Handle partial results and fill gaps with alternative methods (+5 more)

### Community 13 - "AI Payload Generation"
Cohesion: 0.12
Nodes (13): advanced_payload_generation(), ai_generate_payload(), AIPayloadGenerator, AI-powered payload generation system with contextual intelligence, Generate contextual payloads based on target information, Get payloads for specific attack type and complexity, Enhance payloads with contextual information, Generate test cases for the payloads (+5 more)

### Community 14 - "Visual Engine & Dashboard"
Cohesion: 0.10
Nodes (14): create_summary_report(), ModernVisualEngine, process_dashboard(), Beautiful, modern output formatting with animations and colors, Create a beautiful progress bar with cyberpunk styling, Render a beautiful progress bar with multiple styles, Create a live dashboard showing all active processes, Format vulnerability as a beautiful card (+6 more)

### Community 15 - "Target Analysis & Attack Surface"
Cohesion: 0.10
Nodes (14): Enum, Types of recovery actions that can be taken, Enumeration of different target types for intelligent analysis, Common technology stacks for targeted testing, Analyze target and create comprehensive profile, Determine the type of target for appropriate tool selection, Resolve domain to IP addresses, Detect technologies using basic heuristics (+6 more)

### Community 16 - "Caching Layer"
Cohesion: 0.13
Nodes (11): AdvancedCache, clear_cache(), clear_process_cache(), Clear the advanced cache, Advanced caching system with intelligent TTL and LRU eviction, Set value in cache with optional TTL, Delete key from cache, Clear all cache entries (+3 more)

### Community 17 - "HTTP Testing Framework"
Cohesion: 0.15
Nodes (10): http_framework_endpoint(), HTTPTestingFramework, Advanced HTTP testing framework as Burp Suite alternative, Setup HTTP proxy for request interception, Intercept and analyze HTTP requests, Set match/replace rules. Each rule: {'where','pattern','replacement'}, Send a custom request with explicit fields, applying rules., Simple fuzzing: iterate payloads over each parameter individually (Sniper). (+2 more)

### Community 18 - "CTF Workflow Automation"
Cohesion: 0.15
Nodes (10): CTFWorkflowManager, Specialized workflow manager for CTF competitions, Create advanced specialized workflow for CTF challenge with AI-powered optimizat, Generate fallback strategies for when primary approaches fail, Analyze challenge description complexity to adjust time estimates, Create advanced category-specific workflow with parallel execution support, Identify tasks that can be executed in parallel for efficiency, Calculate estimated resource requirements for challenge (+2 more)

### Community 19 - "Process Pool & Scaling"
Cohesion: 0.15
Nodes (11): manual_scale_pool(), ProcessPool, Manually scale the process pool, Intelligent process pool with auto-scaling capabilities, Get result of a submitted task, Worker thread that processes tasks, Monitor pool performance and auto-scale, Add workers to the pool (+3 more)

### Community 20 - "Qwen AI Engine"
Cohesion: 0.19
Nodes (9): QwenAIEngine, Data-collection AI engine with automatic model fallback.     Uses _AIFallbackCha, Generate a complete, working exploit script., Generate a custom pentesting tool/script from a description., Analyse source code for security vulnerabilities., Generate shellcode stub or msfvenom command for a given payload., Generate a minimal PoC for a described vulnerability., Parse raw crawler output (katana/hakrawler/etc.) into structured findings. (+1 more)

### Community 21 - "Chat REPL & Model Routing"
Cohesion: 0.22
Nodes (17): auto_route(), banner(), call_agent(), call_all(), call_claude(), call_model(), call_openai_compat(), list_models() (+9 more)

### Community 22 - "MCP Client & Health"
Cohesion: 0.16
Nodes (13): Aegis360Client, main(), Any, Main entry point for the MCP server., Enhanced client for communicating with the Aegis-360 AI API Server, Initialize the Aegis-360 AI Client          Args:             server_url: URL of, Perform a GET request with optional query parameters.          Args:, Perform a POST request with JSON data.          Args:             endpoint: API (+5 more)

### Community 23 - "MCP Server Logging"
Cohesion: 0.13
Nodes (15): Aegis360Colors, ColoredFormatter, parse_args(), Enhanced formatter with colors and emojis for MCP client - matches server stylin, Parse command line arguments., Enhanced color palette matching the server's ModernVisualEngine.COLORS, Aegis-360 AI Capabilities Reference, FastMCP Framework (MCP protocol bridge) (+7 more)

### Community 24 - "Parameter & Performance Optimization"
Cohesion: 0.15
Nodes (10): ParameterOptimizer, PerformanceMonitor, Advanced performance monitoring with automatic resource allocation, Monitor current system resource usage, Optimize parameters based on current resource usage, Advanced parameter optimization system with intelligent context-aware selection, Advanced parameter optimization with full intelligence, Get base parameters for a tool (+2 more)

### Community 25 - "Attack Chain Builder"
Cohesion: 0.17
Nodes (13): analyze_target(), create_attack_chain(), detect_technologies(), intelligent_smart_scan(), optimize_tool_parameters(), Detect technologies and create technology-specific testing recommendations, Convert AttackChain to dictionary, Analyze target and create comprehensive profile using Claude AI or Decision Engi (+5 more)

### Community 26 - "Burp Suite & Browser Integration"
Cohesion: 0.17
Nodes (10): browser_agent_endpoint(), burpsuite_alternative(), Get recent vulnerabilities found, Spider website to discover endpoints and forms, Setup Chrome browser with security testing options, Very lightweight active tests (reflection check) - safe mode.         Only GET f, AI-powered browser agent for web application inspection, Comprehensive Burp Suite alternative combining HTTP framework and browser agent (+2 more)

### Community 27 - "CTF Challenge Automation"
Cohesion: 0.18
Nodes (8): CTFChallengeAutomator, Advanced automation system for CTF challenge solving, Attempt to automatically solve a CTF challenge, Execute a step with parallel tool execution, Execute a step sequentially, Extract potential flags from tool output, Validate if a string matches common flag formats, Generate manual guidance when automation fails

### Community 28 - "Error Classification"
Cohesion: 0.19
Nodes (9): ErrorType, IntelligentErrorHandler, Enumeration of different error types for intelligent handling, Advanced error handling with automatic recovery strategies, Initialize error pattern recognition, Initialize recovery strategies for different error types, Initialize alternative tools for fallback scenarios, Initialize parameter adjustments for different error types and tools (+1 more)

### Community 29 - "File Operations Management"
Cohesion: 0.16
Nodes (10): FileOperationsManager, Any, Get alternative tool for failed tool, Rebuild command with new parameters, Handle file operations with security and validation, Create a file with the specified content, Modify an existing file, Delete a file or directory (+2 more)

### Community 30 - "Decision Engine"
Cohesion: 0.16
Nodes (8): IntelligentDecisionEngine, Enable advanced parameter optimization, Disable advanced parameter optimization (use legacy), Optimize Prowler parameters, AI-powered tool selection and parameter optimization engine, Initialize tool effectiveness ratings for different target types, Initialize technology detection signatures, Initialize common attack patterns for different scenarios

### Community 31 - "Resource Monitoring"
Cohesion: 0.16
Nodes (8): get_resource_usage(), Get current system resource usage and trends, Internal command execution with enhanced monitoring, Advanced resource monitoring with historical tracking, Get current system resource usage, Get resource usage for specific process, Get resource usage trends, ResourceMonitor

### Community 32 - "Telemetry & Health"
Cohesion: 0.17
Nodes (10): cache_stats(), get_cache_stats(), get_telemetry(), health_check(), Get advanced cache statistics, Collect and manage system telemetry, Get current system metrics, Get telemetry statistics (+2 more)

### Community 33 - "CTF Team Coordination"
Cohesion: 0.19
Nodes (8): create_ctf_team_strategy(), CTFTeamCoordinator, Create optimal team strategy for CTF competition, Coordinate team efforts in CTF competitions, Optimize team strategy based on member skills and challenge types, Estimate solve time for a challenge based on member skills, Assign challenges to team members optimally, Identify challenges that would benefit from team collaboration

### Community 34 - "Failure Recovery & Tech Detection"
Cohesion: 0.17
Nodes (7): FailureRecoverySystem, Advanced technology detection system for context-aware parameter selection, Comprehensive technology detection, Intelligent failure recovery with alternative tool selection, Analyze failure and suggest recovery strategies, Extract tool name from error output, TechnologyDetector

### Community 35 - "Project Documentation"
Cohesion: 0.23
Nodes (13): Smart AI Model Routing (task-to-model assignment logic), BinaryGalaxys — Project Author / Maintainer, Claude Sonnet 4.6 — Exploitation and Reporting AI Model, Contributing Guide for aegis-360-ai, DeepSeek V4 Pro — Recon/Enumeration/VulnAnalysis AI Model, Mafia721/aegis-360-ai — GitHub Repository, Groq — Free-tier AI Provider (Llama, Qwen3, OpenAI OSS), install.sh — Automated Linux/macOS Installer Script (+5 more)

### Community 36 - "CTF Challenge Model"
Cohesion: 0.18
Nodes (9): auto_solve_ctf_challenge(), create_ctf_challenge_workflow(), CTFChallenge, Create specialized workflow for CTF challenge, Attempt to automatically solve a CTF challenge, CTF challenge information, Select appropriate tools based on challenge details, Create category-specific workflow steps (+1 more)

### Community 37 - "Claude AI Engine"
Cohesion: 0.18
Nodes (4): ClaudeAIEngine, Wraps the Anthropic SDK to provide real Claude-powered analysis.     Falls back, Single-turn message with system prompt caching and typed error handling., Streaming single-turn message — used for large outputs (exploit generation).

### Community 38 - "Async Process Management"
Cohesion: 0.17
Nodes (8): EnhancedProcessManager, get_async_task_result(), Get result of asynchronous task, Submit a task to the process pool, Advanced process management with intelligent resource allocation, Execute command asynchronously using process pool, Get result of async task, Terminate process with graceful degradation

### Community 39 - "Attack Chain Steps"
Cohesion: 0.24
Nodes (7): AttackChain, AttackStep, Create an intelligent attack chain based on target profile, Individual step in an attack chain, Represents a sequence of attacks for maximum impact, Add a step to the attack chain, Calculate overall success probability of the attack chain

### Community 40 - "CTFToolManager"
Cohesion: 0.22
Nodes (7): CTFToolManager, Suggest optimal tools for CTF challenge based on description and category, Advanced tool manager for CTF challenges with comprehensive tool arsenal, Get optimized command for CTF tool with intelligent parameter selection, Get all tools for a specific category, Suggest optimal tools based on challenge description and category, suggest_ctf_tools()

### Community 41 - "install.sh"
Cohesion: 0.27
Nodes (10): CodeQL — Source-Level Static Analysis / Raptor Integration, .env-Based API Keys / Secrets Management, err(), info(), log(), install.sh script, install_sudo_tools.sh — Sudo-level Security Tool Installer, warn() (+2 more)

### Community 42 - "Aegis360Cache"
Cohesion: 0.22
Nodes (5): Aegis360Cache, Advanced caching system for command results, Generate cache key from command and parameters, Check if cache entry is expired, Store result in cache

### Community 43 - ".chat()"
Cohesion: 0.22
Nodes (4): _AIFallbackChain, AI engine chain using DeepSeek V4 Pro via OpenRouter as the sole provider.     A, Try each engine in order.         Returns (response_text, engine_name_used)., Returns (response_text, engine_name) — useful for logging which model answered.

### Community 44 - ".get_comprehensive_stats()"
Cohesion: 0.20
Nodes (8): get_performance_dashboard(), get_process_pool_stats(), process_health_check(), Get process pool statistics and performance metrics, Get performance dashboard data, Comprehensive health check of the process management system, Get comprehensive system and process statistics, Get performance summary

### Community 45 - "qwen_full_pipeline()"
Cohesion: 0.20
Nodes (8): qwen_full_pipeline(), qwen_parse_burp(), qwen_parse_scan_logs(), Parse Burp proxy history into structured pentest findings., Normalise raw output from any scan tool into structured findings., Fetch Burp Suite proxy history from the Aegis360 Burp extension (port 9997),, Parse raw output from any scan tool (nmap, nikto, nuclei, dirsearch, etc.)     a, One-shot endpoint: crawl target + fetch Burp history + parse provided     scan l

### Community 46 - "FileUploadTestingFramework"
Cohesion: 0.28
Nodes (6): create_file_upload_testing(), FileUploadTestingFramework, Create file upload vulnerability testing workflow, Specialized framework for file upload vulnerability testing, Generate various test files for upload testing, Create comprehensive file upload testing workflow

### Community 47 - "PerformanceDashboard"
Cohesion: 0.22
Nodes (5): PerformanceDashboard, Monitor system resources and auto-scale, Real-time performance monitoring dashboard, Record command execution for performance tracking, Update system metrics for dashboard

### Community 48 - "RateLimitDetector"
Cohesion: 0.25
Nodes (5): RateLimitDetector, Intelligent rate limiting detection and automatic timing adjustment, Detect rate limiting from response, Recommend timing profile based on rate limit confidence, Adjust timing parameters based on profile

### Community 49 - ".format_tool_status()"
Cohesion: 0.25
Nodes (5): get_parameter_adjustments(), Close the browser instance, Get parameter adjustments for a tool and error type, Automatically adjust tool parameters based on error patterns, Format tool execution status with enhanced highlighting

### Community 50 - "upload_to_github.sh"
Cohesion: 0.46
Nodes (7): check(), err(), info(), log(), upload_to_github.sh script, step(), warn()

### Community 51 - "ColoredFormatter"
Cohesion: 0.40
Nodes (4): ColoredFormatter, Custom formatter with colors and emojis, Setup enhanced logging with colors and formatting, setup_logging()

## Knowledge Gaps
- **7 isolated node(s):** `install_sudo_tools.sh script`, `MCP (Model Context Protocol) — Tool Exposure Protocol`, `Groq — Free-tier AI Provider (Llama, Qwen3, OpenAI OSS)`, `install.sh — Automated Linux/macOS Installer Script`, `workflow_states/ — Persisted Orchestrator Workflow State` (+2 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **98 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `CVEIntelligenceManager` connect `CVE Intelligence & Exploit Search` to `Server Core & Tool Registry`, `Visual Engine & Dashboard`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `IntelligentDecisionEngine` connect `Decision Engine` to `._optimize_checkov_params()`, `._optimize_kube_hunter_params()`, `._optimize_nuclei_params()`, `._optimize_scout_suite_params()`, `Target Profiling & Optimization`, `Server Core & Tool Registry`, `Attack Chain Steps`, `._optimize_trivy_params()`, `Target Analysis & Attack Surface`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Why does `IntelligentErrorHandler` connect `Error Classification` to `.format_tool_status()`, `File Operations Management`, `Server Core & Tool Registry`, `Error Recovery & Resilience`?**
  _High betweenness centrality (0.036) - this node is a cross-community bridge._
- **What connects `install_sudo_tools.sh script`, `MCP (Model Context Protocol) — Tool Exposure Protocol`, `Groq — Free-tier AI Provider (Llama, Qwen3, OpenAI OSS)` to the rest of the system?**
  _7 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Model Orchestration & Workflow` be split into smaller, more focused modules?**
  _Cohesion score 0.05221518987341772 - nodes in this community are weakly interconnected._
- **Should `AI Exploit Generation` be split into smaller, more focused modules?**
  _Cohesion score 0.052244897959183675 - nodes in this community are weakly interconnected._
- **Should `Agent Runtime & Model Providers` be split into smaller, more focused modules?**
  _Cohesion score 0.05574912891986063 - nodes in this community are weakly interconnected._