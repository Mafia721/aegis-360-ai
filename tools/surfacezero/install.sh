#!/usr/bin/env bash
# SurfaceZero v2.1 - Install Script
# For authorized penetration testing only.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*] $*${NC}"; }
success() { echo -e "${GREEN}[+] $*${NC}"; }
warn()    { echo -e "${YELLOW}[!] $*${NC}"; }
error()   { echo -e "${RED}[!] $*${NC}"; exit 1; }

echo -e "${RED}"
cat << 'EOF'
███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝
███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗
╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝
███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
EOF
echo -e "${NC}"
echo -e "${YELLOW}SurfaceZero v2.1 - Installation Script${NC}"
echo -e "${YELLOW}BinaryGalaxys Security | Authorized Penetration Testing Only${NC}"
echo ""

# Check Python version
PYTHON=$(command -v python3 || true)
if [ -z "$PYTHON" ]; then
    error "Python 3 is not installed. Please install Python 3.10+."
fi

PY_VER=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJ=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MIN=$($PYTHON -c "import sys; print(sys.version_info.minor)")

info "Python version: $PY_VER"

if [ "$PY_MAJ" -lt 3 ] || { [ "$PY_MAJ" -eq 3 ] && [ "$PY_MIN" -lt 10 ]; }; then
    error "Python 3.10 or higher is required. Found: $PY_VER"
fi

# Create output directory
mkdir -p output
success "Created output/ directory"

# Detect if we're in a venv
IN_VENV=0
if [ -n "$VIRTUAL_ENV" ]; then
    IN_VENV=1
    info "Virtual environment detected: $VIRTUAL_ENV"
fi

# Install dependencies
info "Installing Python dependencies..."

if [ "$IN_VENV" -eq 1 ]; then
    pip install -r requirements.txt
elif command -v pip3 &>/dev/null; then
    # Try without --break-system-packages first, fall back if needed
    pip3 install -r requirements.txt 2>/dev/null || \
    pip3 install -r requirements.txt --break-system-packages
else
    error "pip3 not found. Install pip or use a virtual environment."
fi

success "Dependencies installed."

# Verify core imports
info "Verifying installation..."
$PYTHON -c "
import sys
missing = []
for pkg in ['click', 'httpx', 'rich', 'bs4']:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f'MISSING: {missing}', file=sys.stderr)
    sys.exit(1)
print('Core imports OK')
"

# Test CLI
info "Testing CLI..."
$PYTHON preloginscan.py --version

echo ""
success "SurfaceZero v2.1 installed successfully!"
echo ""
echo -e "${CYAN}Quick start:${NC}"
echo "  python3 preloginscan.py scan -t https://target.com"
echo "  python3 preloginscan.py scan -t https://target.com --ai-analyze --ai-model claude"
echo "  python3 preloginscan.py --help"
echo ""
echo -e "${YELLOW}Set API keys for AI features:${NC}"
echo "  export ANTHROPIC_API_KEY='sk-ant-...'"
echo "  export DEEPSEEK_API_KEY='sk-...'"
echo ""
echo -e "${RED}For authorized penetration testing only.${NC}"
