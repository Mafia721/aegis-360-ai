# Aegis-360 AI v6.0 — Installation Guide

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 22.04 / Kali 2024+ / macOS 13+ | Kali Linux 2025.1 |
| Python | 3.11+ | 3.13 |
| RAM | 8 GB | 16 GB+ |
| Disk | 20 GB | 50 GB+ |
| CPU | 4 cores | 8+ cores |
| Network | Required | Stable broadband |

> **Windows**: Partial support via WSL2. Native Windows is not fully supported due to security tool dependencies.

---

## Quick Start (Kali/Ubuntu)

```bash
git clone https://github.com/YOUR_ORG/aegis-360-ai.git
cd aegis-360-ai
cp .env.example .env
# Edit .env and fill in your API keys
nano .env
python3 -m venv aegis-360-env
source aegis-360-env/bin/activate
pip install -r requirements.txt
python3 aegis_360_server.py --port 8888
```

---

## Detailed Installation

### 1. Ubuntu 22.04 / 24.04

```bash
# System dependencies
sudo apt-get update && sudo apt-get install -y \
    python3 python3-pip python3-venv git curl wget \
    build-essential libssl-dev libffi-dev python3-dev \
    chromium-browser chromium-chromedriver \
    nmap masscan nikto sqlmap gobuster ffuf \
    hydra john hashcat enum4linux-ng netcat-traditional \
    whois dnsutils netdiscover arp-scan nbtscan

# Clone and enter project
git clone https://github.com/YOUR_ORG/aegis-360-ai.git
cd aegis-360-ai

# Configure environment
cp .env.example .env
nano .env   # fill in your API keys

# Python virtual environment
python3 -m venv aegis-360-env
source aegis-360-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install additional security tools (requires sudo)
sudo bash install_sudo_tools.sh

# Generate MCP config
INSTALL_PATH="$(pwd)"
sed "s|/YOUR/INSTALL/PATH|${INSTALL_PATH}|g" \
    aegis-360-ai-mcp.json.example > aegis-360-ai-mcp.json
echo "MCP config written to aegis-360-ai-mcp.json"
```

### 2. Kali Linux 2024.x / 2025.x

Kali includes most security tools by default. Installation is simpler:

```bash
# Kali already has most tools — just install Python deps
sudo apt-get update && sudo apt-get install -y \
    python3-venv python3-dev build-essential

git clone https://github.com/YOUR_ORG/aegis-360-ai.git
cd aegis-360-ai
cp .env.example .env && nano .env

python3 -m venv aegis-360-env
source aegis-360-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Generate MCP config
INSTALL_PATH="$(pwd)"
sed "s|/YOUR/INSTALL/PATH|${INSTALL_PATH}|g" \
    aegis-360-ai-mcp.json.example > aegis-360-ai-mcp.json
```

### 3. macOS (13 Ventura+)

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://brew.sh/install.sh)"

# Dependencies
brew install python@3.13 git nmap masscan nikto
brew install --cask chromium

git clone https://github.com/YOUR_ORG/aegis-360-ai.git
cd aegis-360-ai
cp .env.example .env && nano .env

python3.13 -m venv aegis-360-env
source aegis-360-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Generate MCP config
INSTALL_PATH="$(pwd)"
sed "s|/YOUR/INSTALL/PATH|${INSTALL_PATH}|g" \
    aegis-360-ai-mcp.json.example > aegis-360-ai-mcp.json
```

> **Note**: Binary analysis tools (angr, pwntools) work fully on macOS. Some Linux-specific tools (AFL++, some Kali tools) require Linux or Docker.

### 4. Windows (via WSL2)

```powershell
# In PowerShell (Admin) — enable WSL2
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2
```

```bash
# Inside WSL2 Ubuntu — follow Ubuntu instructions above
sudo apt-get update && sudo apt-get install -y python3 python3-venv git
# ... continue with Ubuntu steps
```

---

## Python Virtual Environment

```bash
# Create
python3 -m venv aegis-360-env

# Activate (Linux/Mac)
source aegis-360-env/bin/activate

# Activate (Windows WSL2)
source aegis-360-env/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify
python3 -c "import flask, anthropic, fastmcp; print('Core deps OK')"
```

---

## Environment Configuration

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
ANTHROPIC_API_KEY=sk-ant-...        # Required
GROQ_API_KEY=gsk_...                # Required (free at console.groq.com)
OPENROUTER_API_KEY=sk-or-v1-...     # Recommended
```

Optional keys enhance specific capabilities (Shodan, Censys, etc.) — see `.env.example` for full list.

---

## MCP Server Configuration (Claude Desktop)

Generate the MCP config file with your actual install path:

```bash
INSTALL_PATH="$(pwd)"
sed "s|/YOUR/INSTALL/PATH|${INSTALL_PATH}|g" \
    aegis-360-ai-mcp.json.example > aegis-360-ai-mcp.json
cat aegis-360-ai-mcp.json   # verify paths look correct
```

Add the contents to your Claude Desktop MCP config:
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

---

## Security Tools Installation

Aegis360 integrates 150+ external security tools. The `install_sudo_tools.sh` script installs the most common ones:

```bash
sudo bash install_sudo_tools.sh
```

This installs tools via apt-get and Go. Review the script before running to understand what will be installed.

For individual tool categories, see `TOOLS.md`.

---

## Running Aegis360

### Mode 1: Flask Backend + Claude Desktop (Primary)

**Terminal 1** — Start the backend server:
```bash
source aegis-360-env/bin/activate
python3 aegis_360_server.py --port 8888
```

**Claude Desktop** — The MCP client connects automatically when you open Claude Desktop (configured via `aegis-360-ai-mcp.json`).

### Mode 2: CLI / Fallback

```bash
source aegis-360-env/bin/activate

# Interactive chat
python3 hexchat.py

# Lock to specific model
python3 hexchat.py --model llama33

# One-shot agent task
python3 hexchat.py --agent "run nmap scan on 192.168.1.0/24"

# Recon mode
python3 hexchat.py --recon
```

### Mode 3: Direct API (REST)

```bash
# Health check
curl http://127.0.0.1:8888/health

# Execute command via API
curl -X POST http://127.0.0.1:8888/api/command \
  -H "Content-Type: application/json" \
  -d '{"command": "nmap_scan", "target": "192.168.1.1"}'
```

---

## Burp Suite Integration (Optional)

1. Start Burp Suite Professional
2. Enable REST API in Burp: **Project Options → Misc → REST API → Enable**
3. Set API key in `.env`: `BURP_API_KEY=your-burp-api-key`
4. Aegis360 will auto-detect Burp on port 8080 (proxy) and 1337 (REST API)

---

## Verification

```bash
source aegis-360-env/bin/activate

# Test Python imports
python3 -c "
import flask, requests, psutil, fastmcp
import anthropic, openai
from dotenv import load_dotenv
print('All core imports OK')
"

# Test server starts
python3 aegis_360_server.py --port 8888 &
sleep 3
curl -s http://127.0.0.1:8888/health | python3 -m json.tool
kill %1
```

---

## Troubleshooting

### `ModuleNotFoundError`
```bash
# Ensure venv is activated
source aegis-360-env/bin/activate
# Reinstall deps
pip install -r requirements.txt
```

### `bcrypt` / `pwntools` conflict
```bash
pip install bcrypt==4.0.1
pip install pwntools
```

### Port 8888 already in use
```bash
# Find what's using it
lsof -i :8888
# Use a different port
python3 aegis_360_server.py --port 9000
# Update MCP config accordingly
```

### MCP not connecting to Claude Desktop
1. Verify paths in `aegis-360-ai-mcp.json` are absolute and correct
2. Verify Python executable exists: `ls aegis-360-env/bin/python3`
3. Restart Claude Desktop after config changes
4. Check Claude Desktop logs for MCP errors

### `angr` install fails
```bash
# angr has heavy build dependencies
sudo apt-get install -y build-essential python3-dev
pip install angr --no-cache-dir
```

### ChromeDriver version mismatch
```bash
pip install --upgrade webdriver-manager
# Or install matching chromedriver manually
chromedriver --version && chromium-browser --version
```

### API key not found
```bash
# Verify .env file exists and is populated
cat .env | grep -v "^#" | grep "="
# Ensure python-dotenv loads it
python3 -c "from dotenv import load_dotenv; load_dotenv(); import os; print(os.getenv('ANTHROPIC_API_KEY', 'NOT SET')[:10])"
```
