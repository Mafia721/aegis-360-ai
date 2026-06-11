#!/usr/bin/env bash
# ============================================================================
# Aegis-360 AI v6.0 — Automated Installer (Linux / macOS)
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/aegis-360-env"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=11
LOG="${SCRIPT_DIR}/install.log"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*" | tee -a "$LOG"; }
warn() { echo -e "${YELLOW}[!]${NC} $*" | tee -a "$LOG"; }
err()  { echo -e "${RED}[✗]${NC} $*" | tee -a "$LOG"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $*" | tee -a "$LOG"; }

echo "" | tee "$LOG"
echo "   █████╗ ███████╗ ██████╗ ██╗███████╗    ██████╗  ██████╗  ██████╗     █████╗ ██╗" | tee -a "$LOG"
echo "  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚════██╗██╔════╝ ██╔═████╗  ██╔══██╗██║" | tee -a "$LOG"
echo "  ███████║█████╗  ██║  ███╗██║███████╗     █████╔╝███████╗ ██║██╔██║  ███████║██║" | tee -a "$LOG"
echo "  ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ╚═══██╗██╔═══██╗████╔╝██║  ██╔══██║██║" | tee -a "$LOG"
echo "  ██║  ██║███████╗╚██████╔╝██║███████║    ██████╔╝╚██████╔╝╚██████╔╝  ██║  ██║██║" | tee -a "$LOG"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═════╝  ╚═════╝  ╚═════╝  ╚═╝  ╚═╝╚═╝" | tee -a "$LOG"
echo "  aegis-360-ai v6.0 — Installer" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# ── OS Detection ─────────────────────────────────────────────────────────────
OS="$(uname -s)"
info "Detected OS: $OS"

# ── Python Check ─────────────────────────────────────────────────────────────
PYTHON=""
for py in python3.13 python3.12 python3.11 python3; do
    if command -v "$py" &>/dev/null; then
        VER="$($py -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
        MAJOR="${VER%%.*}"; MINOR="${VER##*.}"
        if [ "$MAJOR" -ge "$PYTHON_MIN_MAJOR" ] && [ "$MINOR" -ge "$PYTHON_MIN_MINOR" ]; then
            PYTHON="$py"
            log "Python $VER found at $(command -v $py)"
            break
        fi
    fi
done

[ -z "$PYTHON" ] && err "Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ is required. Install it and retry."

# ── System Dependencies ───────────────────────────────────────────────────────
if [[ "$OS" == "Linux" ]]; then
    if command -v apt-get &>/dev/null; then
        log "Installing system packages via apt-get..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            git curl wget build-essential libssl-dev libffi-dev \
            python3-dev python3-venv \
            nmap nikto sqlmap gobuster ffuf \
            chromium-browser chromium-chromedriver 2>>"$LOG" || \
        warn "Some system packages failed to install — continuing anyway."
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if command -v brew &>/dev/null; then
        log "Installing system packages via Homebrew..."
        brew install nmap nikto sqlmap 2>>"$LOG" || warn "Some brew packages failed — continuing."
    else
        warn "Homebrew not found. Install it from https://brew.sh for best results."
    fi
fi

# ── Virtual Environment ───────────────────────────────────────────────────────
if [ -d "$VENV_DIR" ]; then
    warn "Virtual environment already exists at $VENV_DIR"
    read -rp "  Recreate it? [y/N] " RECREATE
    if [[ "$RECREATE" =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        log "Removed existing venv."
    else
        info "Keeping existing venv."
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    log "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

log "Activating virtual environment..."
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# ── Python Dependencies ───────────────────────────────────────────────────────
log "Upgrading pip..."
pip install --upgrade pip --quiet

log "Installing Python dependencies from requirements.txt..."
pip install -r "${SCRIPT_DIR}/requirements.txt" 2>&1 | tee -a "$LOG" | grep -E "^(Successfully|ERROR|error)" || true

# Verify core imports
log "Verifying core imports..."
"${VENV_DIR}/bin/python3" -c "
import flask, requests, psutil, fastmcp, anthropic, openai
from dotenv import load_dotenv
print('  Core imports: OK')
" || err "Core dependency import failed. Check install.log for details."

# ── Environment File ──────────────────────────────────────────────────────────
ENV_FILE="${SCRIPT_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        log "Created .env from .env.example"
        warn "ACTION REQUIRED: Edit .env and fill in your API keys:"
        warn "  nano ${ENV_FILE}"
    else
        warn ".env.example not found — you must create .env manually."
    fi
else
    info ".env already exists — skipping."
fi

# ── MCP Config ───────────────────────────────────────────────────────────────
MCP_TEMPLATE="${SCRIPT_DIR}/aegis-360-ai-mcp.json.example"
MCP_OUTPUT="${SCRIPT_DIR}/aegis-360-ai-mcp.json"

if [ -f "$MCP_TEMPLATE" ]; then
    if [ ! -f "$MCP_OUTPUT" ] || [[ "${1:-}" == "--force" ]]; then
        sed "s|/YOUR/INSTALL/PATH|${SCRIPT_DIR}|g" "$MCP_TEMPLATE" > "$MCP_OUTPUT"
        log "Generated aegis-360-ai-mcp.json with path: $SCRIPT_DIR"
    else
        info "aegis-360-ai-mcp.json already exists — skipping."
    fi
fi

# ── Optional: Security Tools ──────────────────────────────────────────────────
SUDO_SCRIPT="${SCRIPT_DIR}/install_sudo_tools.sh"
if [ -f "$SUDO_SCRIPT" ]; then
    echo ""
    read -rp "Install additional security tools via install_sudo_tools.sh? (requires sudo) [y/N] " INSTALL_TOOLS
    if [[ "$INSTALL_TOOLS" =~ ^[Yy]$ ]]; then
        log "Running install_sudo_tools.sh..."
        sudo bash "$SUDO_SCRIPT" 2>&1 | tee -a "$LOG"
    else
        info "Skipping security tools installation."
        info "Run 'sudo bash install_sudo_tools.sh' later to install them."
    fi
fi

# ── Final Summary ─────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Installation complete!"
echo ""
info "Next steps:"
echo "  1. Edit .env:          nano ${ENV_FILE}"
echo "  2. Add API keys:       ANTHROPIC_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY"
echo "  3. Start backend:      source aegis-360-env/bin/activate && python3 aegis_360_server.py"
echo "  4. Configure Claude:   Add contents of aegis-360-ai-mcp.json to Claude Desktop config"
echo "  5. Verify:             curl http://127.0.0.1:8888/health"
echo ""
info "Full instructions: INSTALL.md"
info "Deployment guide:  DEPLOYMENT.md"
info "Install log:       $LOG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
