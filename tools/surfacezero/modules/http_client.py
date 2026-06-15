"""
HTTP client base - shared request engine for all modules.
"""

import httpx
import asyncio
from typing import Optional, Dict, Any


class HTTPClient:
    def __init__(self, config: dict):
        self.config = config
        self.timeout = config.get("timeout", 15)
        self.proxy = config.get("proxy")
        self.skip_ssl = config.get("skip_ssl", False)
        self.user_agent = config.get("user_agent", "SurfaceZero/2.1")
        self.cookie = config.get("cookie")

        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if self.cookie:
            self.headers["Cookie"] = self.cookie

    def _build_client(self) -> httpx.AsyncClient:
        kwargs = {
            "headers": self.headers,
            "timeout": self.timeout,
            "verify": not self.skip_ssl,
            "follow_redirects": True,
        }
        # httpx >= 0.23 uses proxy= (single URL); proxies= was removed in 0.28
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return httpx.AsyncClient(**kwargs)

    async def get(self, url: str, extra_headers: Optional[Dict] = None) -> Optional[httpx.Response]:
        async with self._build_client() as client:
            try:
                headers = {**self.headers, **(extra_headers or {})}
                return await client.get(url, headers=headers)
            except Exception:
                return None

    async def post(self, url: str, data: Any = None, json: Any = None, extra_headers: Optional[Dict] = None) -> Optional[httpx.Response]:
        async with self._build_client() as client:
            try:
                headers = {**self.headers, **(extra_headers or {})}
                return await client.post(url, data=data, json=json, headers=headers)
            except Exception:
                return None

    async def options(self, url: str, extra_headers: Optional[Dict] = None) -> Optional[httpx.Response]:
        async with self._build_client() as client:
            try:
                headers = {**self.headers, **(extra_headers or {})}
                return await client.options(url, headers=headers)
            except Exception:
                return None
