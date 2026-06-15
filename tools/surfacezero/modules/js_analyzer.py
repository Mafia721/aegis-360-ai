"""
Module: js
JavaScript file discovery and deep analysis:
- Discovers all JS URLs from page source
- Extracts API endpoints, route definitions
- Detects source map exposure
- Identifies framework fingerprints
- Finds function/variable names hinting at auth logic
"""

import re
import asyncio
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional
from bs4 import BeautifulSoup
from modules.http_client import HTTPClient


# Patterns to extract from JS
JS_ENDPOINT_PATTERNS = [
    r"""(?:fetch|axios\.get|axios\.post|axios\.put|axios\.delete|http\.get|http\.post|ajax|XMLHttpRequest)\s*\(\s*[`'"](\/[^`'"]+)[`'"]""",
    r"""(?:url|endpoint|path|route|baseURL|apiUrl)\s*[:=]\s*[`'"](\/[^`'"]{3,})[`'"]""",
    r"""(?:\/api\/|\/v\d+\/|\/graphql|\/rest\/|\/services\/)[^\s`'"<>]{2,50}""",
    r"""[`'"](/[a-zA-Z0-9_\-\/]{4,80})[`'"]""",
]

FRAMEWORK_SIGNATURES = {
    "React": [r"React\.createElement", r"__REACT_DEVTOOLS", r"react-dom"],
    "Vue": [r"__vue__", r"Vue\.config", r"createApp\("],
    "Angular": [r"ng-version", r"platformBrowserDynamic", r"NgModule"],
    "Next.js": [r"__NEXT_DATA__", r"next/router", r"_next/static"],
    "Nuxt": [r"__NUXT__", r"nuxt-link"],
    "Ember": [r"Ember\.Application", r"ember-cli"],
    "Svelte": [r"__svelte", r"SvelteComponent"],
    "Webpack": [r"webpackChunk", r"__webpack_require__", r"webpack/runtime"],
    "Vite": [r"@vite/client", r"vite/preload-helper"],
}

SENSITIVE_FUNCTION_PATTERNS = [
    r"(?i)(getUser|fetchUser|currentUser|whoAmI|getUserInfo|me\(\))",
    r"(?i)(checkAuth|isAuthenticated|verifyToken|validateSession)",
    r"(?i)(adminPanel|superUser|bypassAuth|skipAuth|devMode)",
    r"(?i)(resetPassword|forgotPassword|changePassword)",
    r"(?i)(uploadFile|fileUpload|s3Upload|blobUpload)",
    r"(?i)(exportData|downloadReport|exportCSV)",
]

# ── False Positive Reduction ───────────────────────────────────────────────────

# Path prefixes that are almost always static assets, not API endpoints
_STATIC_PATH_PREFIXES = (
    "/img/", "/images/", "/image/", "/css/", "/js/", "/fonts/", "/font/",
    "/static/", "/assets/", "/asset/", "/media/", "/dist/", "/build/",
    "/public/", "/icons/", "/icon/", "/logo/", "/logos/", "/svg/",
    "/thumbnails/", "/thumb/", "/pics/", "/pictures/",
)

# File extensions that are never API endpoints
_STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".webp", ".avif",
    ".mp4", ".mp3", ".webm", ".ogg", ".pdf", ".zip", ".gz",
    ".map", ".txt", ".xml", ".yml", ".yaml",
)

HARDCODED_URL_PATTERNS = [
    r"https?://[a-zA-Z0-9\-\.]+\.(internal|local|corp|dev|staging|test|qa|uat)\.[a-zA-Z]{2,}[^\s`'\"<>]*",
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\d]*[^\s`'\"<>]*",
    r"s3://[a-zA-Z0-9\-\.]+[^\s`'\"<>]*",
    r"https://[a-zA-Z0-9\-]+\.s3\.[a-zA-Z0-9\-]+\.amazonaws\.com[^\s`'\"<>]*",
    r"https://storage\.googleapis\.com/[a-zA-Z0-9\-\.\/]+",
    r"https://[a-zA-Z0-9\-]+\.blob\.core\.windows\.net[^\s`'\"<>]*",
]


class JSAnalyzer:
    """Discovers and deep-analyzes JavaScript files."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.verbose = config.get("verbose", False)

    def extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """Extract all JS script src URLs from HTML, including CDN and third-party files."""
        soup = BeautifulSoup(html, "lxml")
        js_urls = []
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            if src:
                full = urljoin(base_url, src)
                js_urls.append(full)
        return list(set(js_urls))

    def extract_inline_scripts(self, html: str) -> List[str]:
        """Extract inline <script> block content."""
        soup = BeautifulSoup(html, "lxml")
        return [tag.get_text() for tag in soup.find_all("script", src=False) if tag.get_text().strip()]

    def _detect_frameworks(self, content: str) -> List[str]:
        detected = []
        for framework, patterns in FRAMEWORK_SIGNATURES.items():
            for p in patterns:
                if re.search(p, content):
                    detected.append(framework)
                    break
        return detected

    def _extract_endpoints(self, content: str) -> List[str]:
        endpoints = set()
        for pattern in JS_ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                # Drop static file extensions
                if m.lower().endswith(_STATIC_EXTENSIONS):
                    continue
                # Drop paths that clearly belong to static asset directories
                m_lower = m.lower()
                if any(m_lower.startswith(pfx) for pfx in _STATIC_PATH_PREFIXES):
                    continue
                # Drop single-segment paths that look like file refs (e.g. "/main.abc123.js")
                if m.count("/") == 1 and "." in m.split("/")[-1]:
                    continue
                if len(m) >= 3:
                    endpoints.add(m)
        return list(endpoints)

    def _detect_sensitive_functions(self, content: str) -> List[str]:
        hits = []
        for pattern in SENSITIVE_FUNCTION_PATTERNS:
            matches = re.findall(pattern, content)
            hits.extend(matches)
        return list(set(hits))

    def _detect_source_maps(self, content: str, js_url: str) -> Optional[Dict]:
        match = re.search(r"//# sourceMappingURL=(.+\.map)", content)
        if match:
            map_ref = match.group(1)
            full_map_url = urljoin(js_url, map_ref) if not map_ref.startswith("http") else map_ref
            return {"js_file": js_url, "map_url": full_map_url, "severity": "HIGH"}
        return None

    def _find_cloud_urls(self, content: str) -> List[Dict]:
        findings = []
        for pattern in HARDCODED_URL_PATTERNS:
            matches = re.findall(pattern, content)
            for m in matches:
                findings.append({"url": m, "severity": "MEDIUM"})
        return findings

    async def _analyze_js_file(self, url: str) -> Dict:
        resp = await self.client.get(url)
        result = {
            "url": url,
            "status": resp.status_code if resp else 0,
            "size": 0,
            "endpoints": [],
            "frameworks": [],
            "sensitive_functions": [],
            "source_map": None,
            "cloud_urls": [],
        }
        if resp and resp.status_code == 200:
            content = resp.text
            result["size"] = len(content)
            result["endpoints"] = self._extract_endpoints(content)
            result["frameworks"] = self._detect_frameworks(content)
            result["sensitive_functions"] = self._detect_sensitive_functions(content)
            result["source_map"] = self._detect_source_maps(content, url)
            result["cloud_urls"] = self._find_cloud_urls(content)
        return result

    async def run(self, html: str, base_url: str) -> Dict:
        js_urls = self.extract_js_urls(html, base_url)
        inline_scripts = self.extract_inline_scripts(html)

        # Analyze all JS files concurrently
        tasks = [self._analyze_js_file(url) for url in js_urls]
        js_results = await asyncio.gather(*tasks, return_exceptions=True)
        js_results = [r for r in js_results if isinstance(r, dict)]

        # Aggregate endpoints from all JS
        all_endpoints = set()
        all_frameworks = set()
        all_sensitive = []
        source_maps = []
        cloud_urls = []

        for r in js_results:
            all_endpoints.update(r.get("endpoints", []))
            all_frameworks.update(r.get("frameworks", []))
            all_sensitive.extend(r.get("sensitive_functions", []))
            if r.get("source_map"):
                source_maps.append(r["source_map"])
            cloud_urls.extend(r.get("cloud_urls", []))

        # Also scan inline scripts
        inline_endpoints = set()
        for script in inline_scripts:
            inline_endpoints.update(self._extract_endpoints(script))

        return {
            "module": "js_analysis",
            "js_files_found": len(js_urls),
            "js_urls": js_urls,
            "js_details": js_results,
            "discovered_endpoints": sorted(list(all_endpoints | inline_endpoints)),
            "frameworks_detected": sorted(list(all_frameworks)),
            "sensitive_function_hints": sorted(list(set(all_sensitive))),
            "source_maps_exposed": source_maps,
            "cloud_storage_urls": cloud_urls,
            "inline_scripts_count": len(inline_scripts),
        }
