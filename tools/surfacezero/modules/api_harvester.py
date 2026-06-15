"""
Module: api_harvester
Discovers and actively retrieves data from unauthenticated API endpoints.

Pipeline:
1. Collect candidate endpoints from JS analysis, path scan, GraphQL, OpenAPI spec
2. Probe each with smart HTTP requests (GET/POST with common payloads)
3. Parse and classify response data (JSON, XML, HTML)
4. Detect data sensitivity (PII, credentials, internal data, user records)
5. Store full retrieved response with metadata for report + AI analysis
"""

import asyncio
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from modules.http_client import HTTPClient


# ─── Candidate API Path Patterns ────────────────────────────────────────────

# Common REST API paths worth probing with GET
GET_API_PATHS = [
    # User / Account endpoints
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/user", "/api/v1/user", "/api/me", "/api/v1/me",
    "/api/accounts", "/api/v1/accounts", "/api/account",
    "/api/profile", "/api/profiles", "/api/v1/profile",
    "/api/members", "/api/v1/members",
    "/api/customers", "/api/v1/customers",
    "/api/employees", "/api/admin/users",

    # Config / Info endpoints
    "/api/config", "/api/v1/config", "/api/settings",
    "/api/v1/settings", "/api/info", "/api/v1/info",
    "/api/status", "/api/v1/status", "/api/health",
    "/api/version", "/api/v1/version",
    "/api/system", "/api/v1/system",
    "/api/environment", "/api/env",

    # Data / Content endpoints
    "/api/data", "/api/v1/data", "/api/v2/data",
    "/api/list", "/api/v1/list",
    "/api/items", "/api/v1/items",
    "/api/records", "/api/v1/records",
    "/api/reports", "/api/v1/reports",
    "/api/logs", "/api/v1/logs", "/api/audit",
    "/api/events", "/api/v1/events",
    "/api/notifications", "/api/v1/notifications",

    # Auth-adjacent (often returns data without full auth)
    "/api/token/info", "/api/auth/info",
    "/api/oauth/userinfo", "/oauth/userinfo",
    "/auth/user", "/auth/me",
    "/.well-known/openid-configuration",

    # Search endpoints (often expose data without auth)
    "/api/search", "/api/v1/search",
    "/api/search?q=a", "/api/v1/search?q=a",
    "/api/autocomplete?q=a", "/api/suggest?q=a",

    # Admin / Internal (misconfigured exposure)
    "/api/admin", "/api/v1/admin",
    "/api/internal", "/api/v1/internal",
    "/api/debug", "/api/v1/debug",
    "/api/metrics", "/api/v1/metrics",
    "/actuator/env", "/actuator/beans",
    "/actuator/mappings", "/actuator/heapdump",

    # File / Asset listing
    "/api/files", "/api/v1/files",
    "/api/documents", "/api/v1/documents",
    "/api/attachments", "/api/uploads",
    "/api/export", "/api/v1/export",

    # Product / Business data
    "/api/products", "/api/v1/products",
    "/api/orders", "/api/v1/orders",
    "/api/transactions", "/api/v1/transactions",
    "/api/inventory", "/api/v1/inventory",
    "/api/payments", "/api/v1/payments",

    # Tenant / Organization
    "/api/tenants", "/api/v1/tenants",
    "/api/organizations", "/api/v1/organizations",
    "/api/teams", "/api/v1/teams",
    "/api/roles", "/api/v1/roles",
    "/api/permissions", "/api/v1/permissions",
]

# POST endpoints to probe with common payloads
POST_API_PROBES = [
    ("/api/graphql",          {"query": "{ __typename }"}),
    ("/graphql",              {"query": "{ __typename }"}),
    ("/api/v1/graphql",       {"query": "{ __typename }"}),
    ("/api/search",           {"query": "test", "limit": 10}),
    ("/api/v1/search",        {"query": "test", "limit": 10}),
    ("/api/auth/refresh",     {"refresh_token": "test"}),
    ("/api/token/refresh",    {"refresh_token": "test"}),
    ("/api/users/search",     {"q": "a"}),
    ("/api/v1/users/search",  {"q": "a"}),
]

# Patterns indicating sensitive data in response
SENSITIVE_DATA_PATTERNS = {
    "User Records":        (r'"(?:username|email|user_id|userId|uid|login)":\s*"[^"]+"', "HIGH"),
    "Password Hash":       (r'"(?:password|passwd|hash|bcrypt|salt)":\s*"[^"]+"', "CRITICAL"),
    "API Keys in Response":(r'"(?:api_key|apiKey|secret|token|access_token)":\s*"[a-zA-Z0-9\-_\.]{16,}"', "CRITICAL"),
    "JWT Token":           (r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*', "CRITICAL"),
    "Email Addresses":     (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', "HIGH"),
    "Phone Numbers":       (r'(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}', "MEDIUM"),
    "Credit Card":         (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "CRITICAL"),
    "SSN":                 (r'\b\d{3}-\d{2}-\d{4}\b', "CRITICAL"),
    "Internal IP":         (r'(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', "MEDIUM"),
    "AWS Key":             (r'AKIA[0-9A-Z]{16}', "CRITICAL"),
    "Private Key":         (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "CRITICAL"),
    "DB Connection":       (r'(?:mongodb|postgresql|mysql|redis)://[^\s"\']+', "CRITICAL"),
    "Admin Flag":          (r'"(?:is_admin|isAdmin|role|admin|superuser)":\s*(?:true|"admin"|"superuser")', "HIGH"),
    "PII Fields":          (r'"(?:dob|date_of_birth|ssn|national_id|passport|aadhaar)":\s*"[^"]+"', "CRITICAL"),
    "Internal Paths":      (r'"(?:path|file|directory|location)":\s*"/(?:etc|home|var|usr|opt|root)[^"]+"', "HIGH"),
    "Stack Trace":         (r'(?:Traceback|at [\w.]+\([\w.]+:\d+\)|Exception in thread)', "MEDIUM"),
    "Debug Info":          (r'"(?:debug|stack|trace|exception|error_detail)":\s*"[^"]+"', "MEDIUM"),
    "S3 Bucket":           (r'https://[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com', "HIGH"),
    "Google Cloud Storage":(r'https://storage\.googleapis\.com/[a-zA-Z0-9\-\./]+', "HIGH"),
}

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


# Service / role email prefixes that are public-facing, not personal PII
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
    """Return True if the email is a well-known service/role address, not personal PII."""
    local = addr.split("@")[0].lower().strip()
    # Strip + extension (e.g. support+tag@example.com → support)
    local = local.split("+")[0]
    return local in _SERVICE_EMAIL_PREFIXES


# What makes a response "interesting" (worth including in full)
INTERESTING_CONTENT_TYPES = [
    "application/json",
    "application/xml",
    "text/xml",
    "application/graphql",
    "text/plain",
]


class APIHarvester:
    """
    Discovers and retrieves data from unauthenticated API endpoints.
    Returns full JSON responses with sensitivity classification.
    """

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.base_url = config.get("target", "").rstrip("/")
        self.verbose = config.get("verbose", False)
        self.aggressive = config.get("aggressive", False)

    # ─── Response Parsing ───────────────────────────────────────────────────

    def _parse_response(self, resp, url: str) -> Optional[Dict]:
        """Parse response into structured data regardless of content type."""
        if not resp or resp.status_code not in [200, 201, 206]:
            return None

        content_type = resp.headers.get("content-type", "").lower()
        size = len(resp.content)

        # Skip tiny responses (likely empty or error pages)
        if size < 10:
            return None

        parsed_data = None
        data_type = "unknown"

        # Try JSON
        if "json" in content_type or resp.text.strip().startswith(("{", "[")):
            try:
                parsed_data = resp.json()
                data_type = "json"
            except Exception:
                pass

        # Try XML
        if parsed_data is None and ("xml" in content_type or resp.text.strip().startswith("<")):
            try:
                root = ET.fromstring(resp.text)
                parsed_data = self._xml_to_dict(root)
                data_type = "xml"
            except Exception:
                pass

        # Plain text / HTML fallback
        if parsed_data is None:
            if any(ct in content_type for ct in INTERESTING_CONTENT_TYPES):
                parsed_data = {"raw_text": resp.text[:2000]}
                data_type = "text"
            else:
                return None  # Skip binary / HTML pages

        # Count records if it's an array
        record_count = None
        if isinstance(parsed_data, list):
            record_count = len(parsed_data)
        elif isinstance(parsed_data, dict):
            # Look for common pagination/count keys
            for key in ["total", "count", "totalCount", "total_count", "size", "length"]:
                if key in parsed_data:
                    record_count = parsed_data[key]
                    break

        return {
            "url": url,
            "status_code": resp.status_code,
            "content_type": content_type,
            "size_bytes": size,
            "data_type": data_type,
            "record_count": record_count,
            "data": parsed_data,
            "headers": dict(resp.headers),
        }

    def _xml_to_dict(self, element) -> dict:
        """Convert XML element tree to dict."""
        result = {}
        for child in element:
            child_data = self._xml_to_dict(child) if len(child) else (child.text or "")
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        if element.attrib:
            result["@attributes"] = element.attrib
        return result

    # ─── Sensitivity Analysis ───────────────────────────────────────────────

    def _classify_sensitivity(self, data: Any, url: str) -> Dict:
        """Scan response data for sensitive patterns and classify findings."""
        text = json.dumps(data) if not isinstance(data, str) else data
        findings = []

        for pattern_name, (pattern, severity) in SENSITIVE_DATA_PATTERNS.items():
            raw_matches = re.findall(pattern, text)
            if not raw_matches:
                continue

            unique = list(set(
                m if isinstance(m, str) else m[0]
                for m in raw_matches
            ))

            # ── FP reduction: filter service emails ──
            if pattern_name == "Email Addresses":
                unique = [e for e in unique if not _is_service_email(e)]
                if not unique:
                    continue

            # ── FP reduction: Luhn check for credit cards ──
            if pattern_name == "Credit Card":
                unique = [c for c in unique if _luhn_check(re.sub(r"\D", "", c))]
                if not unique:
                    continue

            # ── FP reduction: SSN must not resemble a date or version ──
            if pattern_name == "SSN":
                def _looks_like_ssn(s: str) -> bool:
                    parts = s.split("-")
                    if len(parts) != 3:
                        return False
                    # Reject if it looks like a date (e.g. 2024-06-15 won't match SSN pattern,
                    # but "123-45-6789" where first block is year-like)
                    a, b, c = parts
                    # Reject calendar-looking triples (month/day in b and c)
                    if 1 <= int(b) <= 12 and 1 <= int(c) <= 31:
                        return False
                    # Reject version-like (e.g. 1-0-5 too short)
                    if len(a) < 3 or int(a) == 0:
                        return False
                    return True
                unique = [s for s in unique if _looks_like_ssn(s)]
                if not unique:
                    continue

            # ── FP reduction: Phone numbers — require ≥2 distinct matches ──
            if pattern_name == "Phone Numbers" and len(unique) < 2:
                continue

            unique = unique[:5]
            findings.append({
                "type": pattern_name,
                "severity": severity,
                "count": len(raw_matches),
                "samples": [self._redact(s) for s in unique],
            })

        # Overall severity = highest found
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        overall = "INFO"
        if findings:
            overall = max(findings, key=lambda f: severity_rank.get(f["severity"], 0))["severity"]

        # Estimate data exposure scale
        exposure = self._estimate_exposure(data)

        return {
            "overall_severity": overall,
            "sensitive_patterns": findings,
            "exposure_estimate": exposure,
            "is_sensitive": len(findings) > 0,
        }

    def _estimate_exposure(self, data: Any) -> str:
        """Estimate scale of data exposure."""
        if isinstance(data, list):
            count = len(data)
            if count > 1000:
                return f"MASS EXPOSURE: {count}+ records"
            elif count > 100:
                return f"BULK: ~{count} records"
            elif count > 10:
                return f"MULTIPLE: {count} records"
            elif count > 0:
                return f"{count} record(s)"
        elif isinstance(data, dict):
            # Check nested arrays
            for v in data.values():
                if isinstance(v, list) and len(v) > 0:
                    return f"Nested collection: {len(v)} items"
            return "Single object"
        return "Unknown"

    def _redact(self, value: str) -> str:
        """Partially redact sensitive values for safe reporting."""
        if len(value) <= 6:
            return "***"
        visible = max(2, len(value) // 5)
        return value[:visible] + "***" + value[-2:]

    # ─── Endpoint Probing ───────────────────────────────────────────────────

    async def _probe_get(self, path: str) -> Optional[Dict]:
        """Probe a GET endpoint and return parsed result if data is returned."""
        url = self.base_url + path
        resp = await self.client.get(url, extra_headers={
            "Accept": "application/json, application/xml, text/plain, */*",
            "X-Requested-With": "XMLHttpRequest",
        })
        return self._parse_response(resp, url)

    async def _probe_post(self, path: str, payload: dict) -> Optional[Dict]:
        """Probe a POST endpoint with a JSON payload."""
        url = self.base_url + path
        resp = await self.client.post(url, json=payload, extra_headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        result = self._parse_response(resp, url)
        if result:
            result["method"] = "POST"
            result["payload_sent"] = payload
        return result

    async def _probe_with_auth_bypass_headers(self, path: str) -> Optional[Dict]:
        """Try common auth bypass headers on endpoints that return 401/403."""
        url = self.base_url + path
        bypass_headers_list = [
            {"X-Original-URL": path, "X-Rewrite-URL": path},
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"X-Api-Key": "null"},
            {"X-Auth-Token": "guest"},
        ]
        for headers in bypass_headers_list:
            resp = await self.client.get(url, extra_headers={
                "Accept": "application/json",
                **headers,
            })
            result = self._parse_response(resp, url)
            if result:
                result["bypass_headers_used"] = headers
                result["finding_note"] = "AUTHENTICATION BYPASS via header manipulation"
                return result
        return None

    # ─── Discovered Endpoint Integration ────────────────────────────────────

    def _collect_candidates(self, scan_modules: dict) -> List[str]:
        """
        Collect API endpoint candidates from other module results:
        JS analysis, path scan, GraphQL, OpenAPI spec.
        """
        candidates = set(GET_API_PATHS)

        # From JS analysis
        js = scan_modules.get("js_analysis", {})
        for ep in js.get("discovered_endpoints", []):
            if ep.startswith("/") and any(k in ep.lower() for k in [
                "api", "v1", "v2", "v3", "rest", "service", "data",
                "user", "account", "config", "admin", "search", "list"
            ]):
                candidates.add(ep)

        # From path scan accessible paths
        paths = scan_modules.get("paths", {})
        for f in paths.get("all_accessible", []):
            p = f.get("path", "")
            if any(k in p.lower() for k in ["api", "json", "data", "rest"]):
                candidates.add(p)

        # From OpenAPI spec endpoints
        openapi = paths.get("openapi_spec", {})
        if openapi and openapi.get("endpoints_preview"):
            for ep in openapi["endpoints_preview"]:
                # Strip path params, keep base path
                clean = re.sub(r"\{[^}]+\}", "1", ep)
                candidates.add(clean)

        return list(candidates)

    # ─── Main Run ────────────────────────────────────────────────────────────

    async def run(self, scan_modules: dict = None) -> Dict:
        """
        Full unauthenticated API data harvesting pipeline.
        """
        scan_modules = scan_modules or {}
        candidates = self._collect_candidates(scan_modules)

        if self.verbose:
            pass  # Will print in runner

        semaphore = asyncio.Semaphore(self.config.get("threads", 10))
        harvested = []
        auth_bypass_candidates = []

        # Phase 1: GET probes
        async def bounded_get(path):
            async with semaphore:
                return await self._probe_get(path)

        get_tasks = [bounded_get(path) for path in candidates]
        get_results = await asyncio.gather(*get_tasks, return_exceptions=True)

        for result in get_results:
            if isinstance(result, dict) and result:
                sensitivity = self._classify_sensitivity(result["data"], result["url"])
                result["sensitivity"] = sensitivity
                result["method"] = result.get("method", "GET")
                harvested.append(result)

        # Phase 2: POST probes
        async def bounded_post(path, payload):
            async with semaphore:
                return await self._probe_post(path, payload)

        post_tasks = [bounded_post(path, payload) for path, payload in POST_API_PROBES]
        post_results = await asyncio.gather(*post_tasks, return_exceptions=True)

        for result in post_results:
            if isinstance(result, dict) and result:
                sensitivity = self._classify_sensitivity(result["data"], result["url"])
                result["sensitivity"] = sensitivity
                harvested.append(result)

        # Phase 3: Auth bypass attempts on high-value paths (aggressive mode)
        if self.aggressive:
            HIGH_VALUE = [
                "/api/users", "/api/admin", "/api/v1/users",
                "/api/config", "/api/settings", "/api/internal",
            ]
            bypass_tasks = [
                self._probe_with_auth_bypass_headers(path)
                for path in HIGH_VALUE
            ]
            bypass_results = await asyncio.gather(*bypass_tasks, return_exceptions=True)
            for result in bypass_results:
                if isinstance(result, dict) and result:
                    sensitivity = self._classify_sensitivity(result["data"], result["url"])
                    result["sensitivity"] = sensitivity
                    result["auth_bypass"] = True
                    harvested.append(result)

        # ─── Classify and rank results ───────────────────────────────────
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        # Sort by severity
        harvested.sort(
            key=lambda r: severity_rank.get(
                r.get("sensitivity", {}).get("overall_severity", "INFO"), 0
            ),
            reverse=True
        )

        # Separate sensitive from clean
        sensitive_endpoints = [
            r for r in harvested
            if r.get("sensitivity", {}).get("is_sensitive")
        ]
        clean_endpoints = [
            r for r in harvested
            if not r.get("sensitivity", {}).get("is_sensitive")
        ]

        # Severity summary
        sev_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in sensitive_endpoints:
            sev = r.get("sensitivity", {}).get("overall_severity", "INFO")
            sev_summary[sev] = sev_summary.get(sev, 0) + 1

        # Auth bypass hits
        bypass_hits = [r for r in harvested if r.get("auth_bypass")]

        return {
            "module": "api_harvester",
            "endpoints_probed": len(candidates) + len(POST_API_PROBES),
            "endpoints_responding": len(harvested),
            "sensitive_endpoints": sensitive_endpoints,
            "clean_endpoints": clean_endpoints,
            "auth_bypass_hits": bypass_hits,
            "severity_summary": sev_summary,
            "total_sensitive": len(sensitive_endpoints),
            "total_clean": len(clean_endpoints),

            # Full data dump in JSON format for the report
            "full_harvest": [
                {
                    "url": r["url"],
                    "method": r.get("method", "GET"),
                    "status": r["status_code"],
                    "data_type": r["data_type"],
                    "size_bytes": r["size_bytes"],
                    "record_count": r.get("record_count"),
                    "sensitivity": r["sensitivity"],
                    "auth_bypass": r.get("auth_bypass", False),
                    "bypass_headers": r.get("bypass_headers_used"),
                    "retrieved_data": r["data"],  # Full JSON response
                }
                for r in harvested
            ],
        }
