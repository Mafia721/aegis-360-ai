# Aegis-360 AI v1.1.0 — Tool Installation Reference

**Coverage:** 125/129 tools (96.9%) | **Last verified:** 2026-06-15  
**Success rate:** 98.4% | **Server:** `http://127.0.0.1:8888`

Run `install_sudo_tools.sh` to reproduce the full setup on a fresh Kali system.

---

## Quick Start

```bash
# 1. Clone repo and create venv
git clone https://github.com/0x4m4/aegis-360-ai.git
cd aegis-360-ai
python3 -m venv aegis-360-env
source aegis-360-env/bin/activate
pip install -r requirements.txt

# 2. Install system tools (requires sudo)
sudo bash install_sudo_tools.sh

# 3. Copy and fill in API keys
cp .env.example .env   # add ANTHROPIC_API_KEY, GROQ_API_KEY, OPENROUTER_API_KEY

# 4. Start server
python3 aegis_360_server.py --port 8888
```

---

## Category Breakdown

### Essential (8/8)
| Tool | Install Method | Notes |
|------|---------------|-------|
| curl | pre-installed | HTTP client |
| file | pre-installed | File type detection |
| strings | pre-installed | Binary string extraction |
| xxd | pre-installed | Hex dump |
| objdump | pre-installed | Binary disassembly |
| tcpdump | pre-installed | Packet capture |
| wireshark / tshark | pre-installed | Network analysis |
| gdb | pre-installed | Debugger |

---

### Network & Recon (10/10)
| Tool | Install Method | Command |
|------|---------------|---------|
| nmap | pre-installed | `nmap` |
| masscan | pre-installed | `masscan` |
| rustscan | prebuilt `.deb` → `~/.local/bin/` | `rustscan` |
| amass | pre-installed | `amass` |
| subfinder | `go install` → `~/gopath/bin/` | `subfinder` |
| fierce | pre-installed | `fierce` |
| dnsenum | pre-installed | `dnsenum` |
| autorecon | pipx / venv | `autorecon` |
| arp-scan | pre-installed | `arp-scan` |
| nbtscan | pre-installed | `nbtscan` |

---

### Web Security (19/19)
| Tool | Install Method | Command |
|------|---------------|---------|
| gobuster | pre-installed | `gobuster` |
| feroxbuster | pre-installed | `feroxbuster` |
| ffuf | pre-installed | `ffuf` |
| dirb | pre-installed | `dirb` |
| dirsearch | pre-installed | `dirsearch` |
| nikto | pre-installed | `nikto` |
| nuclei | pre-installed | `nuclei` |
| sqlmap | pre-installed | `sqlmap` |
| wpscan | pre-installed | `wpscan` |
| dalfox | `go install` → `~/gopath/bin/` | `dalfox` |
| xsser | cloned → `tools/xsser/` | `xsser` (venv wrapper) |
| wafw00f | pre-installed | `wafw00f` |
| httpx | `go install` → `~/gopath/bin/` | `httpx` |
| katana | `go install` → `~/gopath/bin/` | `katana` |
| hakrawler | `go install` → `~/gopath/bin/` | `hakrawler` |
| gau | `go install` → `~/gopath/bin/` | `gau` |
| waybackurls | `go install` → `~/gopath/bin/` | `waybackurls` |
| wfuzz | pre-installed | `wfuzz` |
| dotdotpwn | cloned → `tools/dotdotpwn/` | `dotdotpwn` (wrapper runs perl from tool dir) |

---

### Electron / Desktop Security (1/1)
| Tool | Install Method | Command |
|------|---------------|---------|
| electronegativity | `npm install -g @doyensec/electronegativity --prefix ~/.local` | `electronegativity -i <app/asar>` |

---

### Pre-Auth Attack Surface (1/1)
| Tool | Install Method | Command |
|------|---------------|---------|
| surfacezero | `pip install -e tools/surfacezero/` in aegis-360-env | `surfacezero scan -t <url>` |

**SurfaceZero v2.1** — Pre-authentication attack surface enumeration + AI analyst.

| Module | What it finds |
|--------|--------------|
| `js` | JS files, endpoints, frameworks, source maps, cloud URLs |
| `secrets` | 45 patterns: AWS/GCP/Azure keys, JWTs, DB URIs, tokens |
| `graphql` | Introspection, mutations, batch queries, field suggestions |
| `cors,headers` | Origin reflection, missing headers, CSP weaknesses |
| `cookies,tokens` | HttpOnly/Secure/SameSite, JWT leaks, weak algorithms |
| `pii` | Email, SSN, credit card, Aadhaar, PAN, phone, address |
| `paths` | 123 paths: .env, swagger, actuator, admin, git, backups |
| `api_harvest` | 114 probes, live JSON retrieval, auth bypass testing |

**MCP Tools exposed:** `surfacezero_scan`, `surfacezero_secrets_scan`, `surfacezero_api_harvest`, `surfacezero_graphql_scan`, `surfacezero_analyze`, `surfacezero_report`, `surfacezero_status`

**Server endpoints:** `/api/surfacezero/scan`, `/api/surfacezero/scan/secrets`, `/api/surfacezero/scan/api-harvest`, `/api/surfacezero/scan/graphql`, `/api/surfacezero/analyze`, `/api/surfacezero/report`, `/api/surfacezero/status`

---

### Vulnerability Scanning (4/4)
| Tool | Install Method | Command |
|------|---------------|---------|
| burpsuite | pre-installed | `burpsuite` |
| zaproxy | `sudo apt install zaproxy` | `zaproxy` |
| jaeles | `go install` → `~/gopath/bin/` | `jaeles` |
| wpscan | pre-installed | `wpscan` |

---

### API Testing (8/8)
| Tool | Install Method | Command |
|------|---------------|---------|
| arjun | cloned → `tools/arjun/` | `arjun` (symlink from venv bin) |
| paramspider | cloned → `tools/paramspider/` | `paramspider` (wrapper) |
| x8 | prebuilt binary → `~/.local/bin/` | `x8` |
| httpie | venv | `httpie` |
| graphql-scanner | custom script → `~/.local/bin/` | `graphql-scanner` |
| jwt-analyzer | custom script → `~/.local/bin/` | `jwt-analyzer` |
| api-schema-analyzer | custom script → `~/.local/bin/` | `api-schema-analyzer` |
| insomnia | placeholder (GUI) | — |

---

### Password & Auth (5/5)
| Tool | Install Method | Command |
|------|---------------|---------|
| hydra | pre-installed | `hydra` |
| john | pre-installed | `john` |
| hashcat | pre-installed | `hashcat` |
| medusa | pre-installed | `medusa` |
| hash-identifier | pre-installed | `hash-identifier` |
| patator | pre-installed | `patator` |
| ophcrack | pre-installed | `ophcrack` |
| hashpump | `pip install hashpumpy` → wrapper at `~/.local/bin/hashpump` | `hashpump -s SIG -d DATA -a ADD -k KEYLEN` |
| hashcat-utils | `sudo apt install hashcat-utils` + wrappers in `~/.local/bin/` | `cap2hccapx`, `combinator`, etc. |

---

### Binary Analysis / Exploit Dev (13/13)
| Tool | Install Method | Command |
|------|---------------|---------|
| ghidra | pre-installed | `ghidra` |
| radare2 | pre-installed | `radare2` |
| gdb | pre-installed | `gdb` |
| gdb-peda | cloned → `~/peda/` + `.gdbinit` | auto-loaded in gdb |
| pwndbg | cloned → `~/pwndbg/` | run `~/pwndbg/setup.sh` (needs sudo) |
| binwalk | pre-installed | `binwalk` |
| checksec | venv → `~/.local/bin/checksec` | `checksec` |
| angr | venv (`pip install angr`) | `python3 -c "import angr"` |
| pwntools | venv (`pip install pwntools`) → `~/.local/bin/pwn` | `pwn` / `python3 -c "from pwn import *"` |
| ROPgadget | venv (`pip install ropgadget`) → `~/.local/bin/ROPgadget` | `ROPgadget --binary <elf>` |
| ropper | `pipx install ropper` | `ropper -f <elf>` |
| one-gadget | `gem install one_gadget` → `~/.local/bin/one-gadget` (ruby3.3 wrapper) | `one-gadget <libc>` |
| libc-database | cloned → `~/tools/libc-database/` | `libc-database <symbol> <offset>` |
| pwninit | prebuilt binary → `~/.local/bin/pwninit` | `pwninit` |

---

### Exploitation (3/3)
| Tool | Install Method | Command |
|------|---------------|---------|
| msfconsole | pre-installed | `msfconsole` |
| msfvenom | pre-installed | `msfvenom` |
| metasploit | wrapper → `~/.local/bin/metasploit` (calls msfconsole) | `metasploit` |

---

### Forensics (16/16)
| Tool | Install Method | Command |
|------|---------------|---------|
| volatility3 / vol / vol3 | `pipx install volatility3` → `~/.local/bin/` | `vol -h` |
| volatility (v2 compat) | wrapper → `~/.local/bin/volatility` (calls vol) | `volatility` |
| foremost | pre-installed | `foremost` |
| scalpel | pre-installed | `scalpel` |
| photorec / testdisk | pre-installed | `photorec`, `testdisk` |
| autopsy | pre-installed | `autopsy` |
| sleuthkit | `sudo apt install sleuthkit` + wrapper | `fls`, `icat`, `img_stat`, `mmls` |
| bulk-extractor | `sudo apt install bulk-extractor` + alias | `bulk-extractor` |
| exiftool | pre-installed | `exiftool` |
| steghide | pre-installed | `steghide` |
| stegsolve | JAR → `~/tools/stegsolve.jar` + wrapper | `stegsolve` (needs java) |
| zsteg | `gem install zsteg` → `~/.local/bin/zsteg` (ruby3.3 wrapper) | `zsteg <file.png>` |
| outguess | `sudo apt install outguess` | `outguess` |
| strings | pre-installed | `strings` |
| binwalk | pre-installed | `binwalk` |
| xxd | pre-installed | `xxd` |

---

### OSINT (12/13)
| Tool | Install Method | Command |
|------|---------------|---------|
| theharvester | pre-installed | `theharvester` |
| recon-ng | pre-installed | `recon-ng` |
| spiderfoot | pre-installed | `spiderfoot` |
| sherlock | `pipx install sherlock-project` | `sherlock <username>` |
| social-analyzer | `pipx install social-analyzer` | `social-analyzer` |
| shodan-cli | pre-installed → alias `~/.local/bin/shodan-cli` | `shodan` (needs `shodan init <API_KEY>`) |
| censys-cli | `pipx install censys` → alias `~/.local/bin/censys-cli` | `censys` (needs API keys) |
| have-i-been-pwned | HIBP API wrapper → `~/.local/bin/have-i-been-pwned` | `have-i-been-pwned <password>` |
| anew | `go install` → `~/gopath/bin/` | `anew` |
| qsreplace | `go install` → `~/gopath/bin/` | `qsreplace` |
| uro | `~/.local/bin/uro` | `uro` |
| exploit-db | alias → `~/.local/bin/exploit-db` (calls searchsploit) | `exploit-db <term>` |
| ~~maltego~~ | intentionally not installed (GUI tool) | `sudo apt install maltego` |

---

### Cloud & Container (10/10)
| Tool | Install Method | Command |
|------|---------------|---------|
| trivy | pre-installed | `trivy` |
| checkov | venv / pipx | `checkov` |
| prowler | pre-installed / pipx | `prowler` |
| scout-suite | pre-installed | `scout-suite` |
| kube-bench | pre-installed | `kube-bench` |
| kube-hunter | pre-installed | `kube-hunter` |
| falco | `sudo apt install falco` (custom repo) | `falco` |
| terrascan | pre-installed | `terrascan` |
| docker-bench-security | custom script → `~/.local/bin/` | `docker-bench-security` |
| clair | docker wrapper → `~/.local/bin/clair` | `clair` (needs Docker) |

---

### Wireless (4/4)
| Tool | Install Method | Command |
|------|---------------|---------|
| aircrack-ng | pre-installed | `aircrack-ng` |
| airodump-ng | pre-installed | `airodump-ng` |
| aireplay-ng | pre-installed | `aireplay-ng` |
| airmon-ng | pre-installed | `airmon-ng` |
| kismet | pre-installed | `kismet` |

---

### Additional Utilities (14/14)
| Tool | Install Method | Command |
|------|---------------|---------|
| enum4linux | pre-installed | `enum4linux` |
| enum4linux-ng | `sudo apt install enum4linux-ng` | `enum4linux-ng` |
| smbmap | pre-installed | `smbmap` |
| rpcclient | pre-installed | `rpcclient` |
| evil-winrm | pre-installed | `evil-winrm` |
| responder | pre-installed | `responder` |
| netexec / nxc | pre-installed | `nxc` |
| impacket | venv | `impacket-secretsdump`, etc. |
| autorecon | venv | `autorecon` |
| frida | `pipx install frida-tools` | `frida`, `frida-trace`, `frida-ps` |
| afl-fuzz | compiled → `tools/aflplusplus/` + symlinks in `~/.local/bin/` | `afl-fuzz` |
| rr | prebuilt → `tools/rr-debugger/` + symlink `~/.local/bin/rr` | `rr record <cmd>` |
| codeql | prebuilt CLI → `tools/codeql/` + symlink `~/.local/bin/codeql` | `codeql` |
| xsstrike | cloned → `tools/xsstrike/` | venv wrapper |

---

## PATH & Environment

All user-space tools are in `~/.local/bin/` which is in `$PATH` on Kali by default.

Large binaries excluded from git (install separately):
| Binary | Size | Install |
|--------|------|---------|
| `tools/aflplusplus/` | 824 MB | compile from source |
| `tools/codeql/` | 1.1 GB | download from GitHub releases |
| `tools/rr-debugger/` | 7 MB | download from GitHub releases |
| `tools/xsser/` | 49 MB | `git clone` |

---

## API Keys Required

Add to `.env` in the project root:

```bash
ANTHROPIC_API_KEY=<key>          # claude.ai
GROQ_API_KEY=<key>               # console.groq.com
OPENROUTER_API_KEY=<key>         # openrouter.ai

# Optional — enables OSINT tools
SHODAN_API_KEY=<key>             # account.shodan.io (then: shodan init <key>)
CENSYS_API_ID=<id>               # search.censys.io/account
CENSYS_API_SECRET=<secret>
HAVE_I_BEEN_PWNED_KEY=<key>      # haveibeenpwned.com/API/Key
```

---

## Verification

```bash
# Start server
source aegis-360-env/bin/activate
python3 aegis_360_server.py --port 8888 &

# Check coverage
curl -s http://localhost:8888/health | python3 -c "
import json,sys; d=json.load(sys.stdin)
print(f'Coverage: {d[\"total_tools_available\"]}/{d[\"total_tools_count\"]}')
print(f'Status: {d[\"status\"]} | Success rate: {d[\"telemetry\"][\"success_rate\"]}')
"
```

Expected output: `Coverage: 123/127 | Status: healthy | Success rate: 98.4%`
