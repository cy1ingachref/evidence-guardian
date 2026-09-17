"""Omni Route — Free AI Provider Router.

Routes LLM requests across multiple free AI providers with automatic failover.
No paid APIs required. Users just need a free API key (or none for some providers).

Supported free providers:
  - Nous Portal (hy3:free) — NOUS_API_KEY
  - Groq — GROQ_API_KEY (free tier)
  - Together — TOGETHER_API_KEY (free tier)
  - OpenRouter — OPENROUTER_API_KEY (free models)
  - Ollama — local, no key needed
  - DeepInfra — DEEPINFRA_API_KEY (free tier)
  - HuggingFace — HF_API_KEY (free inference)

Usage:
    evidence-guardian scan https://example.com --omni

Priority order (auto-selected based on available keys):
    1. Ollama (local, no key)
    2. Groq (fastest free tier)
    3. Nous Portal
    4. Together
    5. OpenRouter
    6. DeepInfra
    7. HuggingFace
"""
from __future__ import annotations

import os
import json
import time
from typing import Any

import requests
from rich.console import Console

console = Console()


class AIProvider:
    """Base class for AI providers."""

    name: str = "base"
    needs_key: bool = True
    env_var: str = ""
    is_free: bool = True

    def __init__(self, api_key: str | None = None, **kwargs: Any):
        self.api_key = api_key or os.environ.get(self.env_var, "")
        self.config = kwargs

    @property
    def is_available(self) -> bool:
        """Check if this provider is available (has key if needed)."""
        if not self.needs_key:
            return True
        return bool(self.api_key)

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        """Send a prompt and return the response."""
        raise NotImplementedError


class NousPortalProvider(AIProvider):
    """Nous Portal hy3:free model."""

    name = "Nous Portal"
    env_var = "NOUS_API_URL"
    url = "https://portal.nousresearch.com/api/v1/chat/completions"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "tencent/hy3:free",
            "messages": messages,
            "temperature": 0.2,
        }

        resp = requests.post(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


class GroqProvider(AIProvider):
    """Groq free tier (fast inference)."""

    name = "Groq"
    env_var = "GROQ_API_KEY"
    url = "https://api.groq.com/openai/v1/chat/completions"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.2,
        }

        resp = requests.post(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


class TogetherProvider(AIProvider):
    """Together AI free tier."""

    name = "Together AI"
    env_var = "TOGETHER_API_KEY"
    url = "https://api.together.xyz/v1/chat/completions"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
            "messages": messages,
            "temperature": 0.2,
        }

        resp = requests.post(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


class OpenRouterProvider(AIProvider):
    """OpenRouter free models."""

    name = "OpenRouter"
    env_var = "OPENROUTER_API_KEY"
    url = "https://openrouter.ai/api/v1/chat/completions"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "meta-llama/llama-3.3-70b-instruct:free",
            "messages": messages,
            "temperature": 0.2,
        }

        resp = requests.post(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


class OllamaProvider(AIProvider):
    """Local Ollama instance (completely free)."""

    name = "Ollama"
    needs_key = False
    env_var = "OLLAMA_URL"
    url = "http://localhost:11434/api/chat"

    def __init__(self, api_key: str | None = None, **kwargs: Any):
        super().__init__(api_key, **kwargs)
        self.base_url = os.environ.get(self.env_var, "http://localhost:11434")

    @property
    def is_available(self) -> bool:
        """Check if Ollama is running locally."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "llama3.3",
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2},
        }

        resp = requests.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"].strip()


class DeepInfraProvider(AIProvider):
    """DeepInfra free tier."""

    name = "DeepInfra"
    env_var = "DEEPINFRA_API_KEY"
    url = "https://api.deepinfra.com/v1/openai/chat/completions"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "meta-llama/Llama-3.3-70B-Instruct",
            "messages": messages,
            "temperature": 0.2,
        }

        resp = requests.post(
            self.url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


class OmniRouter:
    """Routes AI requests across available free providers with failover."""

    PROVIDERS = [
        OllamaProvider,
        GroqProvider,
        NousPortalProvider,
        TogetherProvider,
        OpenRouterProvider,
        DeepInfraProvider,
    ]

    def __init__(self, preferred_provider: str | None = None, **kwargs: Any):
        self.providers: list[AIProvider] = []
        self.current_index = 0
        self.preferred = preferred_provider

        # Initialize providers
        for provider_class in self.PROVIDERS:
            try:
                instance = provider_class(**kwargs)
                if instance.is_available:
                    self.providers.append(instance)
            except Exception:
                continue

        # Reorder if preferred provider specified
        if self.preferred:
            for i, provider in enumerate(self.providers):
                if self.preferred.lower() in provider.name.lower():
                    self.providers.insert(0, self.providers.pop(i))
                    break

    @property
    def has_providers(self) -> bool:
        return len(self.providers) > 0

    @property
    def current_provider(self) -> AIProvider | None:
        if self.providers:
            return self.providers[self.current_index]
        return None

    def get_available_providers(self) -> list[str]:
        """Get list of available provider names."""
        return [p.name for p in self.providers]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        """Route to available provider with automatic failover."""
        if not self.providers:
            raise RuntimeError("No AI providers available. Set a free API key or run Ollama locally.")

        errors = []
        for i, provider in enumerate(self.providers):
            try:
                result = provider.analyze(prompt, system=system)
                if i > 0:
                    console.print(f"[dim]Routed to {provider.name}[/dim]")
                return result
            except Exception as e:
                errors.append(f"{provider.name}: {e}")
                continue

        # All providers failed
        error_msg = "All AI providers failed:\n" + "\n".join(f"  - {e}" for e in errors)
        raise RuntimeError(error_msg)


# Global router instance
_router: OmniRouter | None = None


def get_router(**kwargs: Any) -> OmniRouter:
    """Get or create the global OmniRouter."""
    global _router
    if _router is None:
        _router = OmniRouter(**kwargs)
    return _router


def reset_router() -> None:
    """Reset the global router (e.g., after config change)."""
    global _router
    _router = None


def list_available_providers() -> list[str]:
    """List all available providers based on environment."""
    available = []
    for provider_class in OmniRouter.PROVIDERS:
        try:
            instance = provider_class()
            if instance.is_available:
                available.append(instance.name)
        except Exception:
            continue
    return available
