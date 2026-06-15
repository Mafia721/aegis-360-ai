"""
Module: pii
Detects PII leakage in pre-auth responses:
- Email addresses, phone numbers, SSNs
- Names, DOBs, credit card patterns
- Internal usernames, employee IDs
- API responses leaking user data
"""

import re
import asyncio
from typing import List, Dict
from modules.http_client import HTTPClient


# ── False Positive Reduction Helpers ──────────────────────────────────────────

def _luhn_check(number: str) -> bool:
    """Return True if the digit string passes the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_SERVICE_EMAIL_PREFIXES = frozenset({
    "noreply", "no-reply", "donotreply", "do-not-reply",
    "support", "help", "helpdesk", "service", "services",
    "info", "information", "contact", "hello", "hi",
    "admin", "administrator", "root", "postmaster", "webmaster",
    "billing", "accounts", "sales", "marketing", "team",
    "notifications", "notify", "alerts", "mailer", "bounce",
    "security", "abuse", "privacy", "legal", "feedback",
})


def _is_service_email(addr: str) -> bool:
    local = addr.split("@")[0].lower().split("+")[0]
    return local in _SERVICE_EMAIL_PREFIXES


def _ssn_is_valid(s: str) -> bool:
    """Basic SSN sanity: reject date-like and all-zero segment values."""
    parts = s.split("-")
    if len(parts) != 3:
        return False
    a, b, c = parts
    if int(a) == 0 or int(b) == 0 or int(c) == 0:
        return False
    # Reject if b/c look like a calendar month/day pair (version-/date-like)
    if 1 <= int(b) <= 12 and 1 <= int(c) <= 31:
        return False
    return True


PII_PATTERNS = {
    "Email Address": (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "HIGH"),
    "US Phone Number": (r"(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", "MEDIUM"),
    "SSN (US)": (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
    "Credit Card (Visa)": (r"\b4[0-9]{12}(?:[0-9]{3})?\b", "CRITICAL"),
    "Credit Card (Mastercard)": (r"\b5[1-5][0-9]{14}\b", "CRITICAL"),
    "Credit Card (Amex)": (r"\b3[47][0-9]{13}\b", "CRITICAL"),
    "IP Address (Internal)": (r"(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}", "MEDIUM"),
    "Date of Birth Pattern": (r"\b(?:dob|date_of_birth|birthdate)['\"\s:=]+\d{4}-\d{2}-\d{2}", "HIGH"),
    "Passport Number": (r"\b[A-Z]{1,2}\d{6,9}\b", "HIGH"),
    "Indian Aadhaar": (r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b", "CRITICAL"),
    "Indian PAN": (r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", "HIGH"),
    "Username Exposure": (r"(?i)(?:\"username\"|\"user_name\"|\"login\")['\"\s:=]+['\"]([^'\"]{3,50})['\"]", "MEDIUM"),
    "Full Name": (r"(?i)(?:\"full_name\"|\"fullname\"|\"name\")['\"\s:=]+['\"]([A-Z][a-z]+ [A-Z][a-z]+)['\"]", "MEDIUM"),
    "Address Field": (r"(?i)(?:\"address\"|\"street\")['\"\s:=]+['\"]([^'\"]{10,100})['\"]", "HIGH"),
    "Geolocation Coord": (r"(?:lat|latitude|lng|longitude)['\"\s:=]+(-?\d{1,3}\.\d{4,})", "MEDIUM"),
}

# Additional API response paths to probe for PII
PII_PROBE_PATHS = [
    "/api/users",
    "/api/user",
    "/api/v1/users",
    "/api/v2/users",
    "/api/accounts",
    "/api/profile",
    "/api/me",
    "/api/v1/me",
    "/api/customers",
    "/api/members",
    "/users.json",
    "/accounts.json",
    "/api/search?q=a",
    "/api/v1/search?q=a",
    "/.well-known/openid-configuration",
    "/oauth/.well-known/openid-configuration",
]


class PIIScanner:
    """Detect PII leakage in pre-authentication responses."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.base_url = config.get("target", "").rstrip("/")

    def _scan_for_pii(self, content: str, source_url: str) -> List[Dict]:
        findings = []
        for pii_type, (pattern, severity) in PII_PATTERNS.items():
            matches = re.findall(pattern, content)
            unique_matches = list(set(m if isinstance(m, str) else m[0] for m in matches))

            if not unique_matches:
                continue

            # ── FP reduction per type ──────────────────────────────────────

            if "Credit Card" in pii_type:
                unique_matches = [
                    v for v in unique_matches
                    if _luhn_check(re.sub(r"\D", "", v))
                ]
                if not unique_matches:
                    continue

            if pii_type == "Email Address":
                unique_matches = [e for e in unique_matches if not _is_service_email(e)]
                if not unique_matches:
                    continue

            if pii_type == "SSN (US)":
                unique_matches = [s for s in unique_matches if _ssn_is_valid(s)]
                if not unique_matches:
                    continue

            if pii_type == "US Phone Number":
                # Require ≥2 distinct matches to reduce version-number FPs
                if len(unique_matches) < 2:
                    continue

            if pii_type == "Passport Number":
                # Pattern is broad (letter(s) + 6-9 digits); require ≥7 digits
                unique_matches = [
                    v for v in unique_matches
                    if len(re.sub(r"\D", "", v)) >= 7
                ]
                if not unique_matches:
                    continue

            # ─────────────────────────────────────────────────────────────

            redacted = [self._redact(m) for m in unique_matches[:5]]
            findings.append({
                "type": pii_type,
                "severity": severity,
                "source": source_url,
                "count": len(unique_matches),
                "samples_redacted": redacted,
            })
        return findings

    def _redact(self, value: str) -> str:
        """Partially redact PII for safe reporting."""
        if len(value) <= 4:
            return "***"
        visible = max(2, len(value) // 4)
        return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]

    async def _probe_endpoint(self, path: str) -> List[Dict]:
        url = self.base_url + path
        resp = await self.client.get(url, extra_headers={"Accept": "application/json"})
        if resp and resp.status_code == 200:
            content_type = resp.headers.get("content-type", "")
            if "json" in content_type or "javascript" in content_type or "html" in content_type:
                return self._scan_for_pii(resp.text, url)
        return []

    async def run(self, base_html: str, base_url: str, additional_urls: List[str] = None) -> Dict:
        all_findings = []

        # Scan base HTML
        html_pii = self._scan_for_pii(base_html, base_url)
        all_findings.extend(html_pii)

        # Probe API endpoints for unauthenticated PII
        tasks = [self._probe_endpoint(path) for path in PII_PROBE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

        # Scan any additionally discovered URLs
        if additional_urls:
            for url in additional_urls[:20]:
                resp = await self.client.get(url)
                if resp and resp.status_code == 200:
                    findings = self._scan_for_pii(resp.text, url)
                    all_findings.extend(findings)

        # Deduplicate
        seen = set()
        unique = []
        for f in all_findings:
            key = (f["type"], f["source"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        critical = [f for f in unique if f["severity"] == "CRITICAL"]

        return {
            "module": "pii",
            "findings": unique,
            "total": len(unique),
            "critical_count": len(critical),
            "pii_types_found": list(set(f["type"] for f in unique)),
        }
