#!/usr/bin/env bash
# ============================================================================
# upload_to_github.sh — Private GitHub upload for aegis-360-ai
# ============================================================================
# Usage: bash upload_to_github.sh
# Requirements: git, gh (GitHub CLI) — auto-installs gh if missing
# ============================================================================
set -euo pipefail

REPO_NAME="aegis-360-ai"
REPO_DESC="AI-augmented penetration testing framework by BinaryGalaxys"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
step() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}"
echo "   █████╗ ███████╗ ██████╗ ██╗███████╗    ██████╗  ██████╗  ██████╗"
echo "  ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ╚════██╗██╔════╝ ██╔═████╗"
echo "  ███████║█████╗  ██║  ███╗██║███████╗     █████╔╝███████╗ ██║██╔██║"
echo "  ██╔══██║██╔══╝  ██║   ██║██║╚════██║     ╚═══██╗██╔═══██╗████╔╝██║"
echo "  ██║  ██║███████╗╚██████╔╝██║███████║    ██████╔╝╚██████╔╝╚██████╔╝"
echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ╚═════╝  ╚═════╝  ╚═════╝"
echo -e "${NC}"
echo -e "  ${BOLD}GitHub Upload Script${NC}  —  Private repository"
echo ""

# ── STEP 1: Prerequisites ─────────────────────────────────────────────────────
step "STEP 1 — Checking prerequisites"

if ! command -v git &>/dev/null; then
    err "git is not installed. Install it with: sudo apt install git"
fi
log "git $(git --version | cut -d' ' -f3) found"

if ! command -v gh &>/dev/null; then
    warn "GitHub CLI (gh) not found — installing..."

    if command -v apt-get &>/dev/null; then
        curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
            | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg 2>/dev/null
        sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
            | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install gh -y -qq
        log "GitHub CLI installed"
    else
        err "Cannot auto-install gh on this OS. Install manually: https://cli.github.com/"
    fi
fi
log "gh $(gh --version | head -1 | cut -d' ' -f3) found"

# ── STEP 2: GitHub Authentication ─────────────────────────────────────────────
step "STEP 2 — GitHub Authentication"

if gh auth status &>/dev/null; then
    CURRENT_USER=$(gh api user --jq .login 2>/dev/null || echo "unknown")
    log "Already authenticated as: ${CURRENT_USER}"
else
    warn "Not authenticated. Starting GitHub login..."
    echo ""
    info "You can authenticate via:"
    info "  1. Browser (recommended)"
    info "  2. Personal Access Token (PAT) — https://github.com/settings/tokens"
    echo ""
    gh auth login
    CURRENT_USER=$(gh api user --jq .login)
    log "Authenticated as: ${CURRENT_USER}"
fi

# ── STEP 3: Secret scan ───────────────────────────────────────────────────────
step "STEP 3 — Scanning for secrets before upload"

cd "$SCRIPT_DIR"

SECRETS_FOUND=0
SECRET_FILES=""

# Search for patterns that look like real API keys
while IFS= read -r -d '' file; do
    if grep -qE "sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,}|sk-or-v1-[a-f0-9]{60,}|gsk_[A-Za-z0-9]{50,}" "$file" 2>/dev/null; then
        warn "Possible API key found in: $file"
        SECRET_FILES+="  $file\n"
        SECRETS_FOUND=1
    fi
done < <(find . -type f \( -name "*.py" -o -name "*.js" -o -name "*.env" \
    -o -name "*.yaml" -o -name "*.toml" -o -name "*.json" -o -name "*.sh" \) \
    ! -path "./.git/*" ! -name ".env.example" -print0)

# Check for .env file itself
if [ -f ".env" ]; then
    err ".env file exists in repo root — ABORTING. Remove it or ensure it is in .gitignore before uploading."
fi

if [ "$SECRETS_FOUND" -eq 1 ]; then
    echo ""
    echo -e "${RED}${BOLD}[✗] ABORTING — Possible secrets detected in:${NC}"
    echo -e "${SECRET_FILES}"
    echo -e "${YELLOW}Review the files above, remove any real keys, then re-run this script.${NC}"
    exit 1
fi

log "No secrets detected — safe to upload"

# Also verify .env is in .gitignore
if ! grep -q "^\.env$" .gitignore 2>/dev/null; then
    warn ".env is not in .gitignore — adding it now"
    echo ".env" >> .gitignore
fi

# ── STEP 4: Git repository init / reset ───────────────────────────────────────
step "STEP 4 — Initialising git repository"

if [ -d ".git" ]; then
    warn "Existing .git directory found. This will be used as-is."
    info "If you want a fresh history, delete .git/ and re-run."
else
    git init
    log "Git repository initialised"
fi

git config user.email "binarygalaxys@users.noreply.github.com" 2>/dev/null || true
git config user.name  "BinaryGalaxys" 2>/dev/null || true

# Stage everything (respecting .gitignore)
git add .

# Show what will be committed
echo ""
info "Files staged for commit:"
git diff --cached --name-only | head -40
STAGED=$(git diff --cached --name-only | wc -l)
[ "$STAGED" -gt 40 ] && info "  … and $((STAGED - 40)) more"
echo ""

# Commit
if git diff --cached --quiet; then
    warn "Nothing to commit — repository is clean"
else
    git commit -m "feat: initial release of aegis-360-ai v1.0.0

AI-augmented penetration testing framework.
200+ security tool integrations, MCP bridge for Claude Desktop,
autonomous ReAct agent, smart multi-model AI routing.

Author: BinaryGalaxys"
    log "Initial commit created"
fi

# ── STEP 5: Create private GitHub repository and push ─────────────────────────
step "STEP 5 — Creating private GitHub repository and pushing"

# Check if repo already exists
if gh repo view "${CURRENT_USER}/${REPO_NAME}" &>/dev/null; then
    warn "Repository ${CURRENT_USER}/${REPO_NAME} already exists on GitHub"
    read -rp "  Push to existing repo? [y/N] " PUSH_EXISTING
    if [[ "$PUSH_EXISTING" =~ ^[Yy]$ ]]; then
        if ! git remote get-url origin &>/dev/null; then
            git remote add origin "https://github.com/${CURRENT_USER}/${REPO_NAME}.git"
        fi
        git push -u origin main 2>/dev/null || git push -u origin master 2>/dev/null || \
            err "Push failed. Check your credentials and branch name."
        log "Pushed to existing repository"
    else
        err "Aborted by user."
    fi
else
    gh repo create "${REPO_NAME}" \
        --private \
        --description "${REPO_DESC}" \
        --source=. \
        --remote=origin \
        --push
    log "Repository created and pushed"
fi

# ── STEP 6: Verify ────────────────────────────────────────────────────────────
step "STEP 6 — Verification"

echo ""
gh repo view "${CURRENT_USER}/${REPO_NAME}" --json name,visibility,url \
    --jq '"Name:       " + .name + "\nVisibility: " + .visibility + "\nURL:        " + .url'

echo ""
log "aegis-360-ai successfully uploaded as PRIVATE repository"
echo -e "${GREEN}${BOLD}[+] URL: https://github.com/${CURRENT_USER}/${REPO_NAME}${NC}"
echo ""

# ── Final checklist ───────────────────────────────────────────────────────────
echo -e "${BOLD}Final verification checklist:${NC}"
echo ""

check() {
    local desc="$1" result="$2"
    if [ "$result" -eq 0 ]; then
        echo -e "  ${GREEN}[✓]${NC} $desc"
    else
        echo -e "  ${RED}[✗]${NC} $desc"
    fi
}

# .env not tracked
git ls-files --error-unmatch .env &>/dev/null && ENV_TRACKED=1 || ENV_TRACKED=0
check ".env excluded from git" $ENV_TRACKED

# .env.example present
[ -f ".env.example" ] && EXAMPLE_OK=0 || EXAMPLE_OK=1
check ".env.example present with placeholders" $EXAMPLE_OK

# No hexstrike strings remain
REMAINING=$(grep -r "hexstrike" . --include="*.py" --include="*.sh" --include="*.md" \
    ! -path "./.git/*" 2>/dev/null | wc -l)
[ "$REMAINING" -eq 0 ] && HS_OK=0 || HS_OK=1
check "Zero occurrences of 'hexstrike'" $HS_OK

# Private visibility check
VISIBILITY=$(gh repo view "${CURRENT_USER}/${REPO_NAME}" --json visibility --jq .visibility 2>/dev/null)
[ "$VISIBILITY" = "PRIVATE" ] && VIS_OK=0 || VIS_OK=1
check "Repository visibility: PRIVATE" $VIS_OK

# README present
[ -f "README.md" ] && README_OK=0 || README_OK=1
check "README.md present" $README_OK

echo ""
echo -e "${CYAN}Done! View your private repo at:${NC}"
echo -e "  https://github.com/${CURRENT_USER}/${REPO_NAME}"
echo ""
