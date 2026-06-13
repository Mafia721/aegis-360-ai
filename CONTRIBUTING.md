# Contributing to aegis-360-ai

Thank you for your interest in contributing!

## Workflow

1. **Fork** the repository on GitHub
2. **Clone** your fork: `git clone https://github.com/<you>/aegis-360-ai.git`
3. **Create a branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes** — keep PRs focused and small
5. **Test** your changes (start the server and verify the endpoint works)
6. **Commit**: `git commit -m "feat: short description"`
7. **Push**: `git push origin feature/your-feature-name`
8. **Open a pull request** against the `main` branch

## Commit message convention

```
feat:    new feature or tool integration
fix:     bug fix
refactor: code cleanup without behaviour change
docs:    documentation only
test:    test additions or fixes
chore:   tooling, CI, dependencies
```

## Adding a new tool integration

1. Add the tool execution function to `aegis_360_server.py` inside the appropriate section
2. Register the corresponding MCP tool in `aegis_360_mcp.py`
3. Document the tool in `TOOLS.md` and `CAPABILITIES.md`
4. Update `requirements.txt` if a new Python dependency is needed
5. Test end-to-end via Claude Desktop and `aegis360chat.py`

## Code style

- Python 3.11+ syntax
- No external formatters required, but keep lines under ~120 chars
- Docstrings only where the logic is non-obvious
- Never hardcode API keys, tokens, or personal paths

## Security

If you find a security vulnerability in this tool itself (not a target), please follow
the responsible disclosure process in [SECURITY.md](SECURITY.md) rather than opening
a public issue.
