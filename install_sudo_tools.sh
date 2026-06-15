#!/bin/bash
# Aegis-360 AI v6.0 — System Tool Installer
# Run as: sudo bash install_sudo_tools.sh
# Installs system-level tools and sets up user-space wrappers for 123/127 coverage
set -e

AEGIS_360_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN" "$HOME/tools"

echo "[*] Installing apt tools (requires sudo)..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    zaproxy enum4linux-ng falco \
    hashcat-utils outguess bulk-extractor sleuthkit \
    build-essential python3-dev libssl-dev ruby3.3 2>&1

echo "[*] Installing pipx tools..."
for pkg in volatility3 ropper sherlock-project frida-tools social-analyzer censys shodan; do
    pipx install "$pkg" 2>/dev/null || pipx upgrade "$pkg" 2>/dev/null || true
done

echo "[*] Installing Ruby gems (one_gadget, zsteg)..."
GEM_HOME="$HOME/.local/share/gem/ruby/3.3.0" gem install one_gadget zsteg prime

echo "[*] Installing pwntools + hashpumpy into venv..."
"$AEGIS_360_DIR/aegis-360-env/bin/pip" install pwntools hashpumpy -q

echo "[*] Installing Electronegativity (Electron security scanner)..."
npm install -g @doyensec/electronegativity --prefix "$HOME/.local" 2>&1 | grep -v "^npm warn" || true

echo "[*] Downloading pwninit binary..."
curl -sL -o "$LOCAL_BIN/pwninit" \
    "https://github.com/io12/pwninit/releases/download/3.3.1/pwninit"
chmod +x "$LOCAL_BIN/pwninit"

echo "[*] Cloning helper repos..."
[ ! -d "$HOME/tools/libc-database" ] && \
    git clone https://github.com/niklasb/libc-database "$HOME/tools/libc-database"
[ ! -d "$HOME/peda" ] && git clone https://github.com/longld/peda "$HOME/peda"
[ ! -d "$HOME/pwndbg" ] && git clone https://github.com/pwndbg/pwndbg "$HOME/pwndbg"
grep -q "peda" "$HOME/.gdbinit" 2>/dev/null || echo "source ~/peda/peda.py" >> "$HOME/.gdbinit"

echo "[*] Creating PATH symlinks and wrappers in ~/.local/bin..."

# volatility3
ln -sf "$HOME/.local/bin/vol"  "$LOCAL_BIN/vol3"
ln -sf "$HOME/.local/bin/vol"  "$LOCAL_BIN/volatility3"
printf '#!/bin/bash\nvol "$@"\n' > "$LOCAL_BIN/volatility" && chmod +x "$LOCAL_BIN/volatility"

# Binary exploitation
ln -sf "$AEGIS_360_DIR/aegis-360-env/bin/ROPgadget" "$LOCAL_BIN/ROPgadget"
ln -sf "$LOCAL_BIN/ROPgadget"                        "$LOCAL_BIN/ropgadget"
ln -sf "$AEGIS_360_DIR/aegis-360-env/bin/pwn"        "$LOCAL_BIN/pwn"
ln -sf "$AEGIS_360_DIR/aegis-360-env/bin/checksec"   "$LOCAL_BIN/checksec"

# Web tools from venv
ln -sf "$AEGIS_360_DIR/aegis-360-env/bin/arjun"      "$LOCAL_BIN/arjun"

# paramspider
cat > "$LOCAL_BIN/paramspider" << EOF
#!/bin/bash
"$AEGIS_360_DIR/aegis-360-env/bin/python3" \\
    "$AEGIS_360_DIR/tools/paramspider/paramspider/main.py" "\$@"
EOF
chmod +x "$LOCAL_BIN/paramspider"

# dotdotpwn
cat > "$LOCAL_BIN/dotdotpwn" << EOF
#!/bin/bash
cd "$AEGIS_360_DIR/tools/dotdotpwn" && perl dotdotpwn.pl "\$@"
EOF
chmod +x "$LOCAL_BIN/dotdotpwn"

# rr + afl-fuzz (local builds)
ln -sf "$AEGIS_360_DIR/tools/rr-debugger/bin/rr" "$LOCAL_BIN/rr"
ln -sf "$AEGIS_360_DIR/tools/codeql/codeql"       "$LOCAL_BIN/codeql"
for f in "$AEGIS_360_DIR/tools/aflplusplus/afl-"*; do
    [[ -x "$f" ]] && ln -sf "$f" "$LOCAL_BIN/$(basename "$f")"
done

# one_gadget + zsteg (Ruby gems)
cat > "$LOCAL_BIN/one_gadget" << 'EOF'
#!/bin/bash
GEM_HOME="$HOME/.local/share/gem/ruby/3.3.0" \
GEM_PATH="$HOME/.local/share/gem/ruby/3.3.0" \
ruby3.3 "$HOME/.local/share/gem/ruby/3.3.0/gems/one_gadget-1.10.0/bin/one_gadget" "$@"
EOF
chmod +x "$LOCAL_BIN/one_gadget" && ln -sf "$LOCAL_BIN/one_gadget" "$LOCAL_BIN/one-gadget"

cat > "$LOCAL_BIN/zsteg" << 'EOF'
#!/bin/bash
GEM_HOME="$HOME/.local/share/gem/ruby/3.3.0" \
GEM_PATH="$HOME/.local/share/gem/ruby/3.3.0" \
ruby "$HOME/.local/share/gem/ruby/3.3.0/gems/zsteg-0.2.14/bin/zsteg" "$@"
EOF
chmod +x "$LOCAL_BIN/zsteg"

# hashcat-utils
for bin in /usr/lib/hashcat-utils/*.bin; do
    name=$(basename "$bin" .bin)
    printf '#!/bin/bash\nexec %s "$@"\n' "$bin" > "$LOCAL_BIN/$name" && chmod +x "$LOCAL_BIN/$name"
done
printf '#!/bin/bash\nls /usr/lib/hashcat-utils/*.bin | xargs -I{} basename {} .bin\n' \
    > "$LOCAL_BIN/hashcat-utils" && chmod +x "$LOCAL_BIN/hashcat-utils"

# hashpump (python wrapper)
cat > "$LOCAL_BIN/hashpump" << EOF
#!/bin/bash
"$AEGIS_360_DIR/aegis-360-env/bin/python3" -c "
import sys, hashpumpy, argparse
p = argparse.ArgumentParser(description='Hash Length Extension Attack')
p.add_argument('-s','--signature', required=True)
p.add_argument('-d','--data', required=True)
p.add_argument('-a','--additional', required=True)
p.add_argument('-k','--keylength', type=int, required=True)
p.add_argument('-H','--hash-algorithm', default='sha1', choices=['md5','sha1','sha256','sha512'])
a = p.parse_args()
sig, data = hashpumpy.hashpump(a.signature, a.data, a.additional, a.keylength, a.hash_algorithm)
print('New signature:', sig); print('New string:', data)
" "\$@"
EOF
chmod +x "$LOCAL_BIN/hashpump"

# libc-database
printf '#!/bin/bash\ncd ~/tools/libc-database && ./find "$@"\n' \
    > "$LOCAL_BIN/libc-database" && chmod +x "$LOCAL_BIN/libc-database"

# Convenience aliases
for pair in "metasploit:msfconsole" "exploit-db:searchsploit" \
            "shodan-cli:shodan" "censys-cli:censys" "bulk-extractor:bulk_extractor"; do
    alias_name="${pair%%:*}"; target="${pair#*:}"
    printf '#!/bin/bash\nexec %s "$@"\n' "$target" > "$LOCAL_BIN/$alias_name" && chmod +x "$LOCAL_BIN/$alias_name"
done

# sleuthkit meta-wrapper
printf '#!/bin/bash\necho "Tools: fls icat img_stat mmls fsstat ils istat blkcat"\nfls "$@"\n' \
    > "$LOCAL_BIN/sleuthkit" && chmod +x "$LOCAL_BIN/sleuthkit"

# HIBP wrapper
cat > "$LOCAL_BIN/have-i-been-pwned" << 'EOF'
#!/bin/bash
python3 -c "
import sys, urllib.request, hashlib
if len(sys.argv) < 2: print('Usage: have-i-been-pwned <password>'); sys.exit(1)
h = hashlib.sha1(sys.argv[1].encode()).hexdigest().upper()
prefix, suffix = h[:5], h[5:]
resp = urllib.request.urlopen(f'https://api.pwnedpasswords.com/range/{prefix}').read().decode()
for line in resp.splitlines():
    if line.split(':')[0] == suffix:
        print(f'PWNED: found {line.split(chr(58))[1]} times'); sys.exit(0)
print('SAFE: not in breach database')
" "$@"
EOF
chmod +x "$LOCAL_BIN/have-i-been-pwned"

# stegsolve JAR
STEGSOLVE="$HOME/tools/stegsolve.jar"
[ ! -f "$STEGSOLVE" ] && \
    curl -sL -o "$STEGSOLVE" \
    "https://github.com/Giotino/stegsolve/releases/latest/download/StegSolve.jar" || true
printf '#!/bin/bash\njava -jar %s "$@"\n' "$STEGSOLVE" > "$LOCAL_BIN/stegsolve" && chmod +x "$LOCAL_BIN/stegsolve"

# clair (docker)
printf '#!/bin/bash\ndocker run --rm quay.io/projectquay/clair:4.7.4 "$@" 2>/dev/null || echo "clair: run docker compose up clair"\n' \
    > "$LOCAL_BIN/clair" && chmod +x "$LOCAL_BIN/clair"

echo ""
echo "[*] Done. Tool coverage target: 123/127 (96.9%)"
echo "[*] Start server: cd $AEGIS_360_DIR && source aegis-360-env/bin/activate && python3 aegis_360_server.py --port 8888"
echo "[!] API keys needed in .env: SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET"
