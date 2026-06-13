# Contributing to aegis-360-ai

Thank you for your interest in contributing to **[aegis-360-ai](https://github.com/Mafia721/aegis-360-ai)**!
Maintained by **[BinaryGalaxys](https://github.com/BinaryGalaxys)** — penetration testing & security tooling.

## Workflow

1. **Fork** the repository: [github.com/Mafia721/aegis-360-ai](https://github.com/Mafia721/aegis-360-ai)
2. **Clone** your fork: `git clone https://github.com/<you>/aegis-360-ai.git`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes** — keep PRs focused and small
5. **Test** your changes (start the server and verify the endpoint works)
6. **Commit**: `git commit -m "feat: short description"`
7. **Push**: `git push origin feature/your-feature-name`
8. **Open a pull request** against the `master` branch at [Mafia721/aegis-360-ai](https://github.com/Mafia721/aegis-360-ai/pulls)

## Commit message convention

```
feat:     new feature or tool integration
fix:      bug fix
refactor: code cleanup without behaviour change
docs:     documentation only
test:     test additions or fixes
chore:    tooling, CI, dependencies
```

## Adding a new tool integration

1. Add the tool execution function to `aegis_360_server.py` inside the appropriate section
2. Register the corresponding MCP tool in `aegis_360_mcp.py`
3. Document the tool in `TOOLS.md` and `CAPABILITIES.md`
4. Update `requirements.txt` if a new Python dependency is needed
5. Test end-to-end via Claude Desktop and `aegis360chat.py`

## Adding a new orchestration phase

1. Add the phase to the `WorkflowPhase` enum in `aegis_360_orchestrator.py`
2. Assign it to the correct model set (`DEEPSEEK_PHASES` or `CLAUDE_PHASES`)
3. Update `PHASE_ORDER` to reflect the new sequence
4. Add phase guards if the phase has access restrictions
5. Document the phase in `CAPABILITIES.md`

## Code style

- Python 3.11+ syntax (3.13 recommended)
- No external formatters required — keep lines under ~120 chars
- Docstrings only where the logic is non-obvious
- Never hardcode API keys, tokens, or personal paths
- All new endpoints must be registered in both `aegis_360_server.py` and `aegis_360_mcp.py`

## Security

If you find a security vulnerability in this tool itself (not a target), please follow
the responsible disclosure process in [SECURITY.md](SECURITY.md) rather than opening
a public issue.
