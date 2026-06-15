"""
Module: secrets
Scans JavaScript, HTML, CSS responses for hardcoded secrets:
API keys, tokens, credentials, cloud keys, JWT, etc.
"""

import math
import re
import asyncio
from typing import List, Dict
from modules.http_client import HTTPClient


# ── False Positive Reduction Helpers ──────────────────────────────────────────

def _entropy(s: str) -> float:
    """Shannon entropy of a string in bits per character."""
    if not s:
        return 0.0
    freq: dict = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


_PLACEHOLDER_TOKENS = frozenset({
    "example", "your", "xxx", "test", "demo", "dummy", "placeholder",
    "changeme", "replace", "insert", "todo", "fixme", "sample",
    "abcdefgh", "aabbccdd", "secret", "password", "apikey", "api_key",
    "access_token", "token", "none", "null", "undefined", "false", "true",
    "n/a", "enter", "here", "fill", "add", "put", "set", "key",
})


def _is_placeholder(s: str) -> bool:
    """Return True when the string looks like a placeholder or example value."""
    if len(s) < 4:
        return True
    lower = s.lower()
    if any(tok in lower for tok in _PLACEHOLDER_TOKENS):
        return True
    # Repeated single character (xxxxxxxx, 00000000, AAAAAAA)
    unique_chars = len(set(s))
    if unique_chars <= 2 and len(s) > 4:
        return True
    # Pure sequential digit run (1234567890…)
    stripped = re.sub(r"[^a-zA-Z0-9]", "", s)
    if stripped in ("1234567890", "0123456789", "abcdefghijklmnopqrstuvwxyz"):
        return True
    return False


def _extract_secret_value(full_match: str) -> str:
    """Strip keyword + separator prefix from a full regex match to get the raw value."""
    value = re.sub(r"^[a-zA-Z0-9_\-\.\s]+[=:\s]+", "", full_match)
    return value.strip("'\"` \t\n") or full_match


# Patterns that need entropy + placeholder gating (broad / context-heavy patterns)
_ENTROPY_CHECKED_TYPES = frozenset({
    "Generic API Key", "Generic Secret", "Generic Token", "Password in JS",
    "OAuth Client Secret", "OAuth Client ID", "Bearer Token",
})

# Minimum entropy thresholds per type
_ENTROPY_THRESHOLD = {
    "Password in JS": 2.5,       # Weak passwords are still valid findings
    "Generic API Key": 3.2,
    "Generic Secret": 3.2,
    "Generic Token": 3.2,
    "OAuth Client Secret": 3.2,
    "OAuth Client ID": 3.0,
    "Bearer Token": 3.2,
}

# Context keywords required in a 80-char window around an Internal IP match
_IP_CONTEXT_RE = re.compile(
    r"""(?i)(?:url|host|server|endpoint|connect|target|addr|ip[_\-\s]|"""
    r"""destination|backend|proxy|origin|base_?url|network|subnet|gateway)"""
    r"""[\s\w'":=\-]{0,20}"""
)


# Comprehensive secret patterns mapped to severity
SECRET_PATTERNS = {
    # Cloud Providers
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret Key": (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "GCP API Key": (r"AIza[0-9A-Za-z\-_]{35}", "CRITICAL"),
    "GCP Service Account": (r'"type":\s*"service_account"', "CRITICAL"),
    "Azure Storage Key": (r"AccountKey=[a-zA-Z0-9+/]{88}==", "CRITICAL"),

    # Auth / Identity
    "JWT Token": (r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*", "HIGH"),
    "Bearer Token": (r"(?i)bearer\s+[a-zA-Z0-9\-_\.=]{20,}", "HIGH"),
    "Basic Auth Header": (r"(?i)Authorization:\s*Basic\s+[a-zA-Z0-9+/=]+", "HIGH"),
    "OAuth Client Secret": (r"(?i)client[_-]?secret['\"\s:=]+[a-zA-Z0-9\-_]{16,}", "CRITICAL"),
    "OAuth Client ID": (r"(?i)client[_-]?id['\"\s:=]+[a-zA-Z0-9\-_]{16,}", "MEDIUM"),

    # API Keys
    "Generic API Key": (r"(?i)(api[_-]?key|apikey)['\"\s:=]+[a-zA-Z0-9\-_]{16,}", "HIGH"),
    "Generic Secret": (r"(?i)(secret|private_key|secret_key)['\"\s:=]+[a-zA-Z0-9\-_!@#$%]{12,}", "HIGH"),
    "Generic Token": (r"(?i)(token|access_token)['\"\s:=]+[a-zA-Z0-9\-_\.]{20,}", "HIGH"),
    "Password in JS": (r"(?i)(password|passwd|pwd)['\"\s:=]+['\"][^'\"]{6,}['\"]", "CRITICAL"),

    # SaaS / Integration Keys
    "Stripe Secret Key": (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL"),
    "Stripe Publishable Key": (r"pk_live_[0-9a-zA-Z]{24}", "MEDIUM"),
    "Stripe Test Key": (r"sk_test_[0-9a-zA-Z]{24}", "LOW"),
    "Twilio Account SID": (r"AC[a-z0-9]{32}", "HIGH"),
    "Twilio Auth Token": (r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]", "CRITICAL"),
    "SendGrid Key": (r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "CRITICAL"),
    "Slack Token": (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}", "CRITICAL"),
    "Slack Webhook": (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "HIGH"),
    "GitHub Token": (r"ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}", "CRITICAL"),
    "GitLab Token": (r"glpat-[a-zA-Z0-9\-_]{20}", "CRITICAL"),
    "NPM Token": (r"npm_[a-zA-Z0-9]{36}", "HIGH"),
    "Firebase API Key": (r"(?i)firebase.*['\"][A-Za-z0-9\-_]{39}['\"]", "HIGH"),
    "Mailgun Key": (r"key-[0-9a-zA-Z]{32}", "HIGH"),
    "Heroku API Key": (r"[hH]eroku[^0-9A-Za-z][0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "CRITICAL"),
    "Datadog API Key": (r"(?i)datadog.{0,20}['\"][a-f0-9]{32}['\"]", "HIGH"),
    "Coralogix Token": (r"(?i)coralogix.{0,20}['\"][a-zA-Z0-9\-_]{20,}['\"]", "HIGH"),
    "PagerDuty Key": (r"(?i)pagerduty.{0,20}['\"][a-zA-Z0-9\+/]{20,}['\"]", "HIGH"),
    "Segment Write Key": (r"(?i)segment.{0,20}['\"][a-zA-Z0-9]{32,}['\"]", "HIGH"),
    "Algolia App ID": (r"(?i)algolia.{0,20}['\"][A-Z0-9]{10}['\"]", "MEDIUM"),
    "Algolia Admin Key": (r"(?i)algolia.{0,20}['\"][a-f0-9]{32}['\"]", "HIGH"),

    # Database / Connection Strings
    "MongoDB URI": (r"mongodb(\+srv)?://[^'\"\s]+", "CRITICAL"),
    "PostgreSQL URI": (r"postgresql?://[a-zA-Z0-9\-_]+:[^@\s]+@[^\s]+", "CRITICAL"),
    "MySQL URI": (r"mysql://[a-zA-Z0-9\-_]+:[^@\s]+@[^\s]+", "CRITICAL"),
    "Redis URI": (r"redis://[^'\"\s]+", "HIGH"),
    "JDBC URI": (r"jdbc:[a-z]+://[^'\"\s]+", "HIGH"),

    # Internal / Debug Artifacts
    "Internal IP": (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", "MEDIUM"),
    "Localhost Reference": (r"(?i)(localhost|127\.0\.0\.1):\d{4,5}", "LOW"),
    "Debug Flag": (r"(?i)(debug|DEBUG)\s*[=:]\s*(true|1|on)", "LOW"),
    "Source Map Ref": (r"//# sourceMappingURL=(.+\.map)", "MEDIUM"),
    "Private RSA Key": (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL"),
    "Private PGP Key": (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "CRITICAL"),
}


class SecretsScanner:
    """Scans page responses and JS files for hardcoded secrets."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.verbose = config.get("verbose", False)

    def _scan_content(self, content: str, source_url: str) -> List[Dict]:
        findings = []
        for secret_type, (pattern, severity) in SECRET_PATTERNS.items():
            for m in re.finditer(pattern, content):
                full_match = m.group(0)

                if len(full_match) < 8:
                    continue

                # ── Entropy + placeholder gate for broad generic patterns ──
                if secret_type in _ENTROPY_CHECKED_TYPES:
                    value = _extract_secret_value(full_match)
                    threshold = _ENTROPY_THRESHOLD.get(secret_type, 3.2)
                    if _is_placeholder(value) or _entropy(value) < threshold:
                        continue

                # ── Internal IP: require infrastructure context nearby ──
                if secret_type == "Internal IP":
                    start = max(0, m.start() - 80)
                    end = min(len(content), m.end() + 20)
                    window = content[start:end]
                    if not _IP_CONTEXT_RE.search(window):
                        continue

                findings.append({
                    "type": secret_type,
                    "severity": severity,
                    "match": full_match[:120] + ("..." if len(full_match) > 120 else ""),
                    "source": source_url,
                })
        return findings

    async def _fetch_and_scan(self, url: str) -> List[Dict]:
        resp = await self.client.get(url)
        if resp and resp.status_code == 200:
            return self._scan_content(resp.text, url)
        return []

    async def run(self, js_urls: List[str], base_html: str = "", base_url: str = "") -> Dict:
        """
        Run secrets scan across:
        1. Base HTML of the pre-login page
        2. All discovered JS files
        """
        all_findings = []

        # Scan base HTML
        if base_html:
            html_findings = self._scan_content(base_html, base_url)
            all_findings.extend(html_findings)

        # Scan all JS files concurrently
        tasks = [self._fetch_and_scan(url) for url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)

        # Deduplicate by (type, match)
        seen = set()
        unique = []
        for f in all_findings:
            key = (f["type"], f["match"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Severity counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in unique:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        return {
            "module": "secrets",
            "findings": unique,
            "total": len(unique),
            "severity_summary": severity_counts,
        }
