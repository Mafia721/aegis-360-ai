"""
Module: cors / headers / cookies / tokens
- CORS misconfiguration testing
- Security header audit
- Cookie attribute analysis
- JWT/OAuth token detection in pre-auth flows
"""

import re
import asyncio
import json
import base64
from typing import List, Dict, Optional
from modules.http_client import HTTPClient


# ── Cookie Classification ──────────────────────────────────────────────────────

# Analytics / tracking cookies — missing HttpOnly is expected, not a security finding
_ANALYTICS_COOKIE_PREFIXES = (
    "_ga", "_gid", "_gat", "_gcl", "_gac",          # Google Analytics
    "__utm", "__ga", "ga_",                           # GA variants
    "_fbp", "_fbc", "fbm_", "fb_",                   # Facebook
    "_hjid", "_hj", "hjSession",                     # Hotjar
    "amplitude_", "amp_", "ajs_",                    # Amplitude / Segment
    "_dd_", "dd_",                                    # Datadog RUM
    "__hssc", "__hstc", "__hssrc", "hubspotutk",     # HubSpot
    "intercom-", "intercom_",                         # Intercom
    "mh_",                                            # Mixpanel
    "ki_",                                            # Kissmetrics
    "_ym_", "yabs-",                                  # Yandex Metrika
    "optimizelyEnd", "optly",                         # Optimizely
)

# Session / auth cookies where HttpOnly/Secure absence IS a finding
_SESSION_COOKIE_INDICATORS = (
    "sess", "session", "sid", "token", "auth", "jwt",
    "access", "refresh", "csrf", "xsrf", "login", "user",
    "account", "member", "identity", "credential",
)


def _classify_cookie(name: str) -> str:
    """Return 'analytics', 'session', or 'generic' for a cookie name."""
    lower = name.lower()
    if any(lower.startswith(pfx.lower()) for pfx in _ANALYTICS_COOKIE_PREFIXES):
        return "analytics"
    if any(ind in lower for ind in _SESSION_COOKIE_INDICATORS):
        return "session"
    return "generic"


# Test origins for CORS probing
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://{target_domain}.evil.com",   # Subdomain bypass
    "https://evil{target_domain}",         # Prefix bypass
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "HSTS - forces HTTPS",
        "severity": "HIGH",
    },
    "X-Content-Type-Options": {
        "required": True,
        "expected": "nosniff",
        "description": "Prevents MIME sniffing",
        "severity": "MEDIUM",
    },
    "X-Frame-Options": {
        "required": True,
        "expected_values": ["DENY", "SAMEORIGIN"],
        "description": "Clickjacking protection",
        "severity": "MEDIUM",
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "XSS/injection mitigation policy",
        "severity": "HIGH",
    },
    "X-XSS-Protection": {
        "required": False,
        "description": "Legacy XSS filter (deprecated but notable)",
        "severity": "LOW",
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Controls referrer header leakage",
        "severity": "MEDIUM",
    },
    "Permissions-Policy": {
        "required": True,
        "description": "Feature/browser API access policy",
        "severity": "LOW",
    },
    "Cache-Control": {
        "required": True,
        "description": "Sensitive page caching control",
        "severity": "MEDIUM",
    },
    "X-Powered-By": {
        "required": False,
        "risky": True,
        "description": "Exposes server tech stack",
        "severity": "LOW",
    },
    "Server": {
        "required": False,
        "risky": True,
        "description": "Exposes web server version",
        "severity": "LOW",
    },
}

# CSP dangerous patterns
CSP_DANGEROUS = [
    (r"'unsafe-inline'", "Allows inline scripts - XSS risk", "HIGH"),
    (r"'unsafe-eval'", "Allows eval() - XSS risk", "HIGH"),
    (r"script-src \*", "Wildcard script source", "CRITICAL"),
    (r"default-src \*", "Wildcard default source", "CRITICAL"),
    (r"data:", "Allows data: URIs in script", "MEDIUM"),
    (r"http://", "Allows HTTP (non-HTTPS) sources", "MEDIUM"),
]


class HeadersCORSScanner:
    """CORS, security headers, cookie, and token analysis."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.base_url = config.get("target", "").rstrip("/")
        self.verbose = config.get("verbose", False)

    def _parse_domain(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.base_url).netloc

    async def _test_cors(self, url: str) -> List[Dict]:
        """Test CORS misconfiguration using both OPTIONS preflight and GET requests."""
        domain = self._parse_domain()
        findings = []
        confirmed_origins: set = set()

        for origin_template in CORS_TEST_ORIGINS:
            origin = origin_template.replace("{target_domain}", domain)

            # Step 1: OPTIONS preflight (standard CORS check)
            resp_opts = await self.client.options(
                url,
                extra_headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization, content-type",
                }
            )

            # Step 2: Confirm with an actual GET request (some servers skip preflight)
            resp_get = await self.client.get(
                url,
                extra_headers={"Origin": origin}
            )

            # Collect ACAO from whichever responded positively
            acao, acac = "", ""
            for resp in (resp_opts, resp_get):
                if resp:
                    candidate = resp.headers.get("Access-Control-Allow-Origin", "")
                    if candidate:
                        acao = candidate
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                        break

            if not acao:
                continue

            # Only report if the reflection is confirmed (not just wildcard on any request)
            is_reflected = (acao == origin) or (acao == "*")
            is_null = acao == "null"

            if is_reflected and origin not in confirmed_origins:
                confirmed_origins.add(origin)
                creds = acac.lower() == "true"
                # Wildcard + credentials is an invalid combo per spec — skip as FP
                if acao == "*" and creds:
                    continue
                findings.append({
                    "url": url,
                    "test_origin": origin,
                    "reflected_origin": acao,
                    "credentials_allowed": creds,
                    "verified_via": "GET+OPTIONS",
                    "severity": "CRITICAL" if creds else "HIGH",
                    "description": (
                        "CORS origin reflected with credentials=true"
                        if creds else "CORS origin reflected"
                    ),
                })

            if is_null and "null" not in confirmed_origins:
                confirmed_origins.add("null")
                creds = acac.lower() == "true"
                findings.append({
                    "url": url,
                    "test_origin": "null",
                    "reflected_origin": "null",
                    "credentials_allowed": creds,
                    "verified_via": "GET+OPTIONS",
                    "severity": "HIGH",
                    "description": "null origin allowed — file:// / sandboxed iframe bypass",
                })

        return findings

    async def _audit_headers(self, url: str) -> Dict:
        """Audit security headers on a given URL."""
        resp = await self.client.get(url)
        if not resp:
            return {"url": url, "error": "No response"}

        findings = []
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, meta in SECURITY_HEADERS.items():
            h_lower = header.lower()
            present = h_lower in resp_headers

            if meta.get("required") and not present:
                findings.append({
                    "header": header,
                    "status": "MISSING",
                    "severity": meta["severity"],
                    "description": meta["description"],
                })
            elif meta.get("risky") and present:
                findings.append({
                    "header": header,
                    "value": resp_headers[h_lower],
                    "status": "EXPOSED",
                    "severity": meta["severity"],
                    "description": meta["description"],
                })
            elif present and meta.get("expected"):
                val = resp_headers[h_lower]
                if meta["expected"].lower() not in val.lower():
                    findings.append({
                        "header": header,
                        "value": val,
                        "status": "MISCONFIGURED",
                        "severity": meta["severity"],
                        "description": f"Expected '{meta['expected']}' but got '{val}'",
                    })

        # Specific CSP analysis
        csp = resp_headers.get("content-security-policy", "")
        csp_findings = []
        if csp:
            for pattern, desc, sev in CSP_DANGEROUS:
                if re.search(pattern, csp, re.IGNORECASE):
                    csp_findings.append({"pattern": pattern, "description": desc, "severity": sev})
        elif not csp:
            csp_findings.append({"pattern": "N/A", "description": "CSP header absent", "severity": "HIGH"})

        return {
            "url": url,
            "status_code": resp.status_code,
            "missing_or_weak_headers": findings,
            "csp_issues": csp_findings,
            "raw_headers": dict(resp.headers),
        }

    def _analyze_cookies(self, headers: dict) -> List[Dict]:
        """Analyze Set-Cookie headers for missing security attributes."""
        cookie_issues = []
        set_cookies = []

        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookies.append(v)

        for cookie_str in set_cookies:
            name = cookie_str.split("=")[0].strip()
            lower = cookie_str.lower()
            cookie_type = _classify_cookie(name)
            issues = []

            # Analytics / tracking cookies: HttpOnly missing is expected.
            # Only flag Secure absence (transmitting over HTTP is still wrong).
            if cookie_type == "analytics":
                if "secure" not in lower:
                    issues.append({
                        "attribute": "Secure",
                        "severity": "LOW",
                        "reason": "Analytics cookie sent over HTTP (low risk)",
                        "cookie_type": "analytics",
                    })
            else:
                # Session or generic cookie — apply full security check
                httponly_sev = "HIGH" if cookie_type == "session" else "MEDIUM"
                secure_sev   = "HIGH" if cookie_type == "session" else "MEDIUM"

                if "httponly" not in lower:
                    issues.append({
                        "attribute": "HttpOnly",
                        "severity": httponly_sev,
                        "reason": "JS can read this cookie (XSS risk)",
                        "cookie_type": cookie_type,
                    })
                if "secure" not in lower:
                    issues.append({
                        "attribute": "Secure",
                        "severity": secure_sev,
                        "reason": "Cookie transmitted over HTTP",
                        "cookie_type": cookie_type,
                    })
                if "samesite" not in lower:
                    issues.append({
                        "attribute": "SameSite",
                        "severity": "MEDIUM",
                        "reason": "CSRF risk - no SameSite attribute",
                        "cookie_type": cookie_type,
                    })
                elif "samesite=none" in lower and "secure" not in lower:
                    issues.append({
                        "attribute": "SameSite=None without Secure",
                        "severity": "HIGH",
                        "reason": "Invalid combination per RFC 6265bis",
                        "cookie_type": cookie_type,
                    })

            if issues:
                cookie_issues.append({
                    "cookie_name": name,
                    "cookie_type": cookie_type,
                    "issues": issues,
                })

        return cookie_issues

    def _decode_jwt(self, token: str) -> Optional[Dict]:
        """Decode JWT payload without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            payload = parts[1]
            # Add padding
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return None

    async def _detect_tokens(self, url: str) -> List[Dict]:
        """Detect JWT/OAuth tokens in pre-auth responses."""
        resp = await self.client.get(url)
        if not resp:
            return []

        token_findings = []

        # Check response body for JWTs
        jwt_pattern = r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*"
        body_matches = re.findall(jwt_pattern, resp.text)
        for token in body_matches:
            decoded = self._decode_jwt(token)
            finding = {
                "type": "JWT in response body",
                "token_preview": token[:40] + "...",
                "severity": "HIGH",
                "url": url,
                "decoded_payload": decoded,
            }
            # Check algorithm
            if decoded and decoded.get("alg", "").lower() in ["none", "hs256"]:
                finding["risk_note"] = f"Weak algorithm: {decoded.get('alg')} - susceptible to alg:none or brute-force"
                finding["severity"] = "CRITICAL"
            token_findings.append(finding)

        # Check headers for token leakage
        for h, v in resp.headers.items():
            if re.search(jwt_pattern, v):
                token_findings.append({
                    "type": "JWT in response header",
                    "header": h,
                    "severity": "HIGH",
                    "url": url,
                })

        return token_findings

    async def run(self, urls: List[str] = None) -> Dict:
        """Run all header/CORS/cookie/token checks."""
        if not urls:
            urls = [self.base_url, self.base_url + "/login", self.base_url + "/api"]

        # Run all checks
        cors_findings = []
        header_findings = []
        cookie_findings = []
        token_findings = []

        for url in urls[:5]:  # Limit to avoid noise
            cors = await self._test_cors(url)
            cors_findings.extend(cors)

            headers = await self._audit_headers(url)
            header_findings.append(headers)

            # Cookie analysis from first response
            resp = await self.client.get(url)
            if resp:
                cookies = self._analyze_cookies(dict(resp.headers))
                cookie_findings.extend(cookies)

            tokens = await self._detect_tokens(url)
            token_findings.extend(tokens)

        return {
            "module": "headers_cors_tokens",
            "cors_findings": cors_findings,
            "header_audit": header_findings,
            "cookie_issues": cookie_findings,
            "token_leakage": token_findings,
            "total_cors": len(cors_findings),
            "total_header_issues": sum(len(h.get("missing_or_weak_headers", [])) for h in header_findings),
            "total_cookie_issues": len(cookie_findings),
            "total_token_leaks": len(token_findings),
        }
