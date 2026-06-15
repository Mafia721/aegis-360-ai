"""
Model Router - Unified AI interface for SurfaceZero AI Analyst.
Supports: Claude (Anthropic), DeepSeek, Ollama (local), OpenAI, Gemini
"""

import os
import json
import httpx
from typing import Optional
from rich.console import Console

console = Console()

# Model aliases → provider mapping
MODEL_ALIASES = {
    # Claude
    "claude":          ("anthropic", "claude-sonnet-4-6"),
    "claude-sonnet":   ("anthropic", "claude-sonnet-4-6"),
    "claude-haiku":    ("anthropic", "claude-haiku-4-5-20251001"),
    "claude-opus":     ("anthropic", "claude-opus-4-8"),

    # DeepSeek
    "deepseek":        ("deepseek", "deepseek-reasoner"),
    "deepseek-r1":     ("deepseek", "deepseek-reasoner"),
    "deepseek-chat":   ("deepseek", "deepseek-chat"),

    # OpenAI
    "gpt4":            ("openai", "gpt-4o"),
    "gpt-4o":          ("openai", "gpt-4o"),
    "gpt-4o-mini":     ("openai", "gpt-4o-mini"),

    # Gemini
    "gemini":          ("gemini", "gemini-1.5-flash"),
    "gemini-flash":    ("gemini", "gemini-1.5-flash"),
    "gemini-pro":      ("gemini", "gemini-1.5-pro"),

    # Ollama (local) - format: ollama:modelname
    # e.g. ollama:llama3, ollama:mistral, ollama:deepseek-r1:7b
}


class ModelRouter:
    """Routes AI requests to the appropriate provider."""

    def __init__(self, model_str: str, config: dict = None):
        self.raw_model = model_str
        self.config = config or {}
        self.provider, self.model_id = self._resolve(model_str)

    def _resolve(self, model_str: str) -> tuple:
        if model_str.startswith("ollama:"):
            return ("ollama", model_str.split(":", 1)[1])
        if model_str in MODEL_ALIASES:
            return MODEL_ALIASES[model_str]
        # Try exact match as provider:model
        if ":" in model_str:
            parts = model_str.split(":", 1)
            return (parts[0], parts[1])
        # Default: treat as anthropic claude model
        return ("anthropic", model_str)

    def _get_key(self, provider: str) -> Optional[str]:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "deepseek":  "DEEPSEEK_API_KEY",
            "openai":    "OPENAI_API_KEY",
            "gemini":    "GEMINI_API_KEY",
        }
        env_var = env_map.get(provider)
        if env_var:
            key = os.environ.get(env_var) or self.config.get(env_var.lower())
            return key
        return None

    async def complete(self, system: str, user: str, max_tokens: int = 4096) -> str:
        """Route to correct provider and return completion."""
        if self.provider == "anthropic":
            return await self._claude(system, user, max_tokens)
        elif self.provider == "deepseek":
            return await self._deepseek(system, user, max_tokens)
        elif self.provider == "openai":
            return await self._openai(system, user, max_tokens)
        elif self.provider == "gemini":
            return await self._gemini(system, user, max_tokens)
        elif self.provider == "ollama":
            return await self._ollama(system, user, max_tokens)
        else:
            raise ValueError(f"Unknown provider: {self.provider}. Valid: anthropic, deepseek, openai, gemini, ollama")

    async def _claude(self, system: str, user: str, max_tokens: int) -> str:
        key = self._get_key("anthropic")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY not set. Export it or use --api-key.")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model_id,
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                }
            )
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

    async def _deepseek(self, system: str, user: str, max_tokens: int) -> str:
        key = self._get_key("deepseek")
        if not key:
            raise ValueError("DEEPSEEK_API_KEY not set.")

        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(
                "https://api.deepseek.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model_id,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                }
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def _openai(self, system: str, user: str, max_tokens: int) -> str:
        key = self._get_key("openai")
        if not key:
            raise ValueError("OPENAI_API_KEY not set.")

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model_id,
                    "max_tokens": max_tokens,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                }
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]

    async def _gemini(self, system: str, user: str, max_tokens: int) -> str:
        key = self._get_key("gemini")
        if not key:
            raise ValueError("GEMINI_API_KEY not set.")

        combined = f"{system}\n\n{user}"
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_id}:generateContent?key={key}",
                json={
                    "contents": [{"parts": [{"text": combined}]}],
                    "generationConfig": {"maxOutputTokens": max_tokens},
                }
            )
            resp.raise_for_status()
            return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

    async def _ollama(self, system: str, user: str, max_tokens: int) -> str:
        """Local Ollama — no API key needed."""
        ollama_host = self.config.get("ollama_host", "http://localhost:11434")
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(
                f"{ollama_host}/api/chat",
                json={
                    "model": self.model_id,
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "options": {"num_predict": max_tokens},
                }
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]

    def describe(self) -> str:
        return f"{self.provider}/{self.model_id}"
