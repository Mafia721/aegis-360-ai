"""
Module: paths / api / openapi
- Directory/path brute-force for pre-auth resources
- REST API endpoint discovery
- Swagger/OpenAPI spec detection
- WebDAV/file upload endpoint detection
- Backup/debug file exposure
"""

import asyncio
import httpx
from typing import List, Dict, Optional
from modules.http_client import HTTPClient


# Pre-auth sensitive paths to check
SENSITIVE_PATHS = [
    # Admin panels
    "/admin", "/admin/", "/administrator", "/wp-admin", "/management",
    "/panel", "/control", "/dashboard", "/backend",

    # API meta endpoints
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/swagger", "/api/swagger.json", "/api/swagger.yaml",
    "/api/openapi.json", "/api/openapi.yaml", "/api-docs",
    "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/redoc", "/redoc.html", "/.well-known/openid-configuration",

    # Debug / dev artifacts
    "/.env", "/.env.local", "/.env.production", "/.env.staging",
    "/debug", "/debug/pprof", "/phpinfo.php", "/info.php",
    "/test", "/tests", "/dev", "/development",
    "/.git", "/.git/config", "/.git/HEAD",
    "/.svn", "/.hg", "/.DS_Store",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",

    # Source maps
    "/app.js.map", "/main.js.map", "/bundle.js.map", "/vendor.js.map",
    "/static/js/main.chunk.js.map",

    # Backup files
    "/backup", "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/db.sql", "/database.sql", "/site.tar.gz",
    "/web.config", "/web.config.bak", "/.htaccess", "/.htpasswd",

    # Config files
    "/config.json", "/config.yaml", "/config.yml", "/settings.json",
    "/appsettings.json", "/application.yml", "/application.properties",
    "/secrets.json", "/credentials.json",

    # Health / monitoring
    "/health", "/healthz", "/health-check", "/ping",
    "/status", "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/actuator/mappings", "/actuator/beans",
    "/__health", "/internal/health",

    # WebDAV / file endpoints
    "/webdav", "/dav", "/files", "/uploads", "/media",
    "/documents", "/attachments", "/assets",

    # GraphQL / alternate API paths
    "/graphql", "/graphiql", "/playground", "/api/graphql",

    # Version / build info
    "/version", "/version.json", "/build-info", "/build.json",
    "/manifest.json", "/package.json", "/_manifest",

    # JWKS / OAuth
    "/.well-known/jwks.json",
    "/.well-known/oauth-authorization-server",
    "/oauth/token", "/oauth/authorize",
    "/auth/token", "/auth/login",

    # Common framework paths
    "/__webpack_hmr", "/__vite_ping",
    "/rails/info/properties", "/rails/info/routes",
    "/telescope", "/telescope/requests",  # Laravel Telescope
    "/horizon",  # Laravel Horizon
    "/nova",    # Laravel Nova
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class PathScanner:
    """Enumerate pre-auth accessible paths and APIs."""

    def __init__(self, config: dict):
        self.config = config
        self.client = HTTPClient(config)
        self.base_url = config.get("target", "").rstrip("/")
        self.aggressive = config.get("aggressive", False)
        self.verbose = config.get("verbose", False)

    async def _probe_path(self, path: str) -> dict:
        url = self.base_url + path
        resp = await self.client.get(url)
        if resp is None:
            return None

        if resp.status_code in [200, 301, 302, 403, 405, 500]:
            content_type = resp.headers.get("content-type", "")
            size = len(resp.content) if resp.content else 0

            severity = "LOW"
            if resp.status_code == 200:
                if any(k in path for k in [".env", "config", "secret", "credential", "backup", "dump", "swagger", "openapi", "actuator"]):
                    severity = "CRITICAL"
                elif any(k in path for k in ["admin", "debug", "phpinfo", ".git", ".svn", "webdav"]):
                    severity = "HIGH"
                elif any(k in path for k in ["api", "graphql", "health", "metrics", "version"]):
                    severity = "MEDIUM"
            elif resp.status_code == 403:
                severity = "INFO"  # Exists but blocked

            return {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "size": size,
                "content_type": content_type,
                "severity": severity,
                "interesting": resp.status_code == 200 and size > 0,
            }
        return None

    async def _test_http_methods(self, url: str) -> List[str]:
        """Check which HTTP methods are allowed on a URL."""
        allowed = []
        # Use proxy= (httpx >= 0.23 / 0.28 compatible)
        proxy = self.config.get("proxy")
        client_kwargs = {
            "verify": not self.config.get("skip_ssl"),
            "timeout": 10,
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        async with httpx.AsyncClient(**client_kwargs) as client:
            for method in HTTP_METHODS:
                try:
                    resp = await client.request(
                        method, url,
                        headers={"User-Agent": self.config.get("user_agent", "SurfaceZero/2.1")}
                    )
                    if resp.status_code not in [405, 501]:
                        allowed.append(f"{method}:{resp.status_code}")
                except Exception:
                    pass
        return allowed

    async def _detect_openapi(self, results: List[Dict]) -> Optional[Dict]:
        """If OpenAPI/Swagger found, fetch and summarize it."""
        swagger_paths = ["/swagger.json", "/openapi.json", "/api/swagger.json", "/api/openapi.json", "/api-docs"]
        for path in swagger_paths:
            url = self.base_url + path
            resp = await self.client.get(url)
            if resp and resp.status_code == 200:
                try:
                    spec = resp.json()
                    paths_count = len(spec.get("paths", {}))
                    endpoints = list(spec.get("paths", {}).keys())[:30]
                    info = spec.get("info", {})
                    return {
                        "spec_url": url,
                        "title": info.get("title", "Unknown"),
                        "version": info.get("version", "Unknown"),
                        "endpoint_count": paths_count,
                        "endpoints_preview": endpoints,
                        "has_security_schemes": bool(spec.get("securityDefinitions") or spec.get("components", {}).get("securitySchemes")),
                    }
                except Exception:
                    pass
        return None

    async def run(self) -> Dict:
        """Run path enumeration."""
        semaphore = asyncio.Semaphore(self.config.get("threads", 10))

        async def bounded_probe(path):
            async with semaphore:
                return await self._probe_path(path)

        tasks = [bounded_probe(path) for path in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in results if isinstance(r, dict) and r is not None]

        accessible = [r for r in results if r["status"] == 200]
        forbidden = [r for r in results if r["status"] == 403]
        redirected = [r for r in results if r["status"] in [301, 302]]
        errors = [r for r in results if r["status"] == 500]

        critical_finds = [r for r in accessible if r["severity"] in ["CRITICAL", "HIGH"]]

        openapi = await self._detect_openapi(results)

        method_findings = []
        if self.aggressive:
            for r in accessible[:5]:
                methods = await self._test_http_methods(r["url"])
                if methods:
                    method_findings.append({"url": r["url"], "allowed_methods": methods})

        return {
            "module": "paths",
            "total_probed": len(SENSITIVE_PATHS),
            "accessible_200": len(accessible),
            "forbidden_403": len(forbidden),
            "redirected_30x": len(redirected),
            "server_errors_500": len(errors),
            "critical_finds": critical_finds,
            "all_accessible": accessible,
            "openapi_spec": openapi,
            "http_method_findings": method_findings,
        }
