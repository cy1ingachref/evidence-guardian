"""Omni Route — Free AI Provider Router.

Routes LLM requests across multiple free AI providers with automatic failover.
No paid APIs required. Users just need a free API key (or none for some providers).

Free Provider Matrix:
┌─────────────────┬──────────────────────────────────────────┬───────────────────┐
│ Provider        │ Free Models                              │ Key / Setup       │
├─────────────────┼──────────────────────────────────────────┼───────────────────┤
│ Ollama          │ llama3.3, codellama, mistral, etc.       │ Local, no key     │
│ Groq            │ llama-3.3-70b, llama-3.1-8b, mixtral     │ GROQ_API_KEY      │
│ Nous Portal     │ hy3:free                                 │ NOUS_API_KEY      │
│ Together        │ llama-3.3-70b-turbo, mixtral, qwen       │ TOGETHER_API_KEY  │
│ OpenRouter      │ 20+ free models (see FREE_MODELS)        │ OPENROUTOR_API_KEY│
│ Fireworks       │ llama-v3p1-70b-instruct                  │ FIREWORKS_API_KEY │
│ Mistral         │ mistral-small-latest                     │ MISTRAL_API_KEY   │
│ DeepInfra       │ llama-3.3-70b                            │ DEEPINFRA_API_KEY │
│ HuggingFace     │ llama-3.3-70b, mistral-7b                │ HF_API_KEY        │
└─────────────────┴──────────────────────────────────────────┴───────────────────┘

Usage:
    evidence-guardian scan https://example.com --omni
    evidence-guardian scan https://example.com --omni --provider groq --model llama-3.1-8b-instant

Priority order (auto-selected based on available keys):
    1. Ollama (local, no key)
    2. Groq (fastest free tier)
    3. Nous Portal
    4. Together
    5. OpenRouter (most free models)
    6. Fireworks
    7. Mistral
    8. DeepInfra
    9. HuggingFace
"""
from __future__ import annotations

import os
import json
import time
import random
from typing import Any

import requests
from rich.console import Console

console = Console()


# ─── OpenRouter Free Models (as of 2025) ────────────────────────────────────
# These models have ":free" suffix on OpenRouter — no credits required.
# Reference: https://openrouter.ai/models?fmt=cards&order=newest&price=free
OPENROUTER_FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "meta-llama/llama-3.1-8b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "meta-llama/llama-3.2-1b-instruct:free",
    "meta-llama/llama-3.1-405b-instruct:free",
    "mistralai/mistral-7b-instruct:free",
    "mistralai/mistral-nemo:free",
    "microsoft/phi-3.5-mini-128k-instruct:free",
    "google/gemma-2-27b-it:free",
    "google/gemma-2-9b-it:free",
    "qwen/qwen-2.5-72b-instruct:free",
    "qwen/qwen-2-vl-72b-instruct:free",
    "qwen/qwen-2.5-7b-instruct:free",
    "qwen/qwen-2.5-coder-32b-instruct:free",
    "deepseek/deepseek-r1-distill-llama-70b:free",
    "sao10k/l3.1-euris-70b:free",
    "sao10k/l3-lunaris-8b:free",
    "nvidia/llama-3.1-nemotron-70b-instruct:free",
    "undi95/toppy-m-7b:free",
    "gryphe/mythomax-l2-13b:free",
    "meta-llama/llama-3-8b-instruct:free",
    "meta-llama/llama-3.2-11b-vision-instruct:free",
    "microsoft/phi-3-medium-128k-instruct:free",
    "microsoft/phi-3-mini-128k-instruct:free",
]


# ─── Base Provider ───────────────────────────────────────────────────────────

class AIProvider:
    """Base class for AI providers."""

    name: str = "base"
    needs_key: bool = True
    env_var: str = ""
    default_model: str = ""

    def __init__(self, api_key: str | None = None, model: str | None = None, **kwargs: Any):
        self.api_key = api_key or os.environ.get(self.env_var, "")
        self.model = model or self.default_model
        self.config = kwargs

    @property
    def is_available(self) -> bool:
        """Check if this provider is available."""
        if not self.needs_key:
            return True
        return bool(self.api_key)

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        """Send a prompt and return the response."""
        raise NotImplementedError


# ─── Ollama (Local) ─────────────────────────────────────────────────────────

class OllamaProvider(AIProvider):
    """Local Ollama instance — completely free, no key needed."""

    name = "Ollama"
    needs_key = False
    env_var = "OLLAMA_URL"
    url = "http://localhost:11434/api/chat"
    default_model = "llama3.3"

    def __init__(self, api_key: str | None = None, model: str | None = None, **kwargs: Any):
        super().__init__(api_key, model, **kwargs)
        self.base_url = os.environ.get(self.env_var, "http://localhost:11434")

    @property
    def is_available(self) -> bool:
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
            "model": self.model,
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


# ─── Groq (Free Tier) ───────────────────────────────────────────────────────

class GroqProvider(AIProvider):
    """Groq free tier — fast inference."""

    name = "Groq"
    env_var = "GROQ_API_KEY"
    url = "https://api.groq.com/openai/v1/chat/completions"
    default_model = "llama-3.3-70b-versatile"

    FREE_MODELS = [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "llama3-70b-8192",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma2-9b-it",
        "gemma-7b-it",
    ]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── Nous Portal (hy3:free) ─────────────────────────────────────────────────

class NousPortalProvider(AIProvider):
    """Nous Portal hy3:free model."""

    name = "Nous Portal"
    env_var = "NOUS_API_KEY"
    url = "https://portal.nousresearch.com/api/v1/chat/completions"
    default_model = "tencent/hy3:free"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── Together AI (Free Tier) ────────────────────────────────────────────────

class TogetherProvider(AIProvider):
    """Together AI free tier."""

    name = "Together AI"
    env_var = "TOGETHER_API_KEY"
    url = "https://api.together.xyz/v1/chat/completions"
    default_model = "meta-llama/Llama-3.3-70B-Instruct-Turbo"

    FREE_MODELS = [
        "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
        "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "mistralai/Mixtral-8x7B-Instruct-v0.1",
        "Qwen/Qwen2.5-7B-Instruct-Turbo",
    ]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── OpenRouter (20+ Free Models) ───────────────────────────────────────────

class OpenRouterProvider(AIProvider):
    """OpenRouter — access 20+ free models from multiple providers.

    OpenRouter provides a unified API to access many models for free.
    Models suffixed with ":free" require no credits.
    """

    name = "OpenRouter"
    env_var = "OPENROUTER_API_KEY"
    url = "https://openrouter.ai/api/v1/chat/completions"
    default_model = "meta-llama/llama-3.3-70b-instruct:free"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/cy1ingachref/evidence-guardian",
            "X-Title": "EvidenceGuardian",
        }

        resp = requests.post(
            self.url,
            headers=headers,
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    @classmethod
    def list_free_models(cls) -> list[str]:
        """Return list of available free models on OpenRouter."""
        return OPENROUTER_FREE_MODELS.copy()

    @classmethod
    def get_random_free_model(cls) -> str:
        """Get a random free model (for load balancing)."""
        return random.choice(OPENROUTER_FREE_MODELS)


# ─── Fireworks AI (Free Tier) ───────────────────────────────────────────────

class FireworksProvider(AIProvider):
    """Fireworks AI free tier."""

    name = "Fireworks"
    env_var = "FIREWORKS_API_KEY"
    url = "https://api.fireworks.ai/inference/v1/chat/completions"
    default_model = "accounts/fireworks/models/llama-v3p1-70b-instruct"

    FREE_MODELS = [
        "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "accounts/fireworks/models/llama-v3p1-8b-instruct",
        "accounts/fireworks/models/mixtral-8x7b-instruct",
        "accounts/fireworks/models/mixtral-22b-instruct",
        "accounts/fireworks/models/qwen2p5-72b-instruct",
    ]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── Mistral AI (Free Tier) ─────────────────────────────────────────────────

class MistralProvider(AIProvider):
    """Mistral AI free tier (with rate limits)."""

    name = "Mistral"
    env_var = "MISTRAL_API_KEY"
    url = "https://api.mistral.ai/v1/chat/completions"
    default_model = "mistral-small-latest"

    FREE_MODELS = [
        "mistral-small-latest",
        "mistral-medium-latest",
        "open-mistral-7b",
        "open-mixtral-8x7b",
    ]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── DeepInfra (Free Tier) ──────────────────────────────────────────────────

class DeepInfraProvider(AIProvider):
    """DeepInfra free tier."""

    name = "DeepInfra"
    env_var = "DEEPINFRA_API_KEY"
    url = "https://api.deepinfra.com/v1/openai/chat/completions"
    default_model = "meta-llama/Llama-3.3-70B-Instruct"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
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


# ─── HuggingFace (Free Inference API) ────────────────────────────────────────

class HuggingFaceProvider(AIProvider):
    """HuggingFace free inference API."""

    name = "HuggingFace"
    env_var = "HF_API_KEY"
    url = "https://api-inference.huggingface.co/models/{model}/v1/chat/completions"
    default_model = "meta-llama/Llama-3.3-70B-Instruct"

    FREE_MODELS = [
        "meta-llama/Llama-3.3-70B-Instruct",
        "meta-llama/Llama-3.1-8B-Instruct",
        "mistralai/Mistral-7B-Instruct-v0.3",
        "Qwen/Qwen2.5-72B-Instruct",
        "microsoft/Phi-3.5-mini-instruct",
        "google/gemma-2-27b-it",
    ]

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 1024,
        }

        api_url = self.url.format(model=self.model)

        resp = requests.post(
            api_url,
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


# ─── OmniRouter ──────────────────────────────────────────────────────────────

class OmniRouter:
    """Routes AI requests across available free providers with failover."""

    PROVIDERS = [
        OllamaProvider,
        GroqProvider,
        NousPortalProvider,
        TogetherProvider,
        OpenRouterProvider,
        FireworksProvider,
        MistralProvider,
        DeepInfraProvider,
        HuggingFaceProvider,
    ]

    # Provider display info for CLI
    PROVIDER_INFO = [
        {"name": "Ollama", "env": "OLLAMA_URL", "key_needed": False, "desc": "Local, no key"},
        {"name": "Groq", "env": "GROQ_API_KEY", "key_needed": True, "desc": "Fast free tier"},
        {"name": "Nous Portal", "env": "NOUS_API_KEY", "key_needed": True, "desc": "hy3:free model"},
        {"name": "Together AI", "env": "TOGETHER_API_KEY", "key_needed": True, "desc": "Free tier"},
        {"name": "OpenRouter", "env": "OPENROUTER_API_KEY", "key_needed": True, "desc": "20+ free models"},
        {"name": "Fireworks", "env": "FIREWORKS_API_KEY", "key_needed": True, "desc": "Free tier"},
        {"name": "Mistral", "env": "MISTRAL_API_KEY", "key_needed": True, "desc": "Free tier (rate limited)"},
        {"name": "DeepInfra", "env": "DEEPINFRA_API_KEY", "key_needed": True, "desc": "Free tier"},
        {"name": "HuggingFace", "env": "HF_API_KEY", "key_needed": True, "desc": "Free inference"},
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


# ─── Module-level helpers ────────────────────────────────────────────────────

_router: OmniRouter | None = None


def get_router(**kwargs: Any) -> OmniRouter:
    """Get or create the global OmniRouter."""
    global _router
    if _router is None:
        _router = OmniRouter(**kwargs)
    return _router


def reset_router() -> None:
    """Reset the global router."""
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


def get_provider(provider_name: str) -> dict[str, Any]:
    """Get provider info by name."""
    for info in OmniRouter.PROVIDER_INFO:
        if info["name"].lower() == provider_name.lower():
            has_key = bool(os.environ.get(info["env"], ""))
            return {**info, "available": has_key or not info["key_needed"]}
    return {}


def list_all_providers() -> list[dict[str, Any]]:
    """List all providers with their status."""
    result = []
    for info in OmniRouter.PROVIDER_INFO:
        has_key = bool(os.environ.get(info["env"], ""))
        available = has_key or not info["key_needed"]
        result.append({**info, "available": available, "has_key": has_key})
    return result


# ─── Free Model Discovery ────────────────────────────────────────────────────

def list_free_models(provider: str) -> list[str]:
    """List free models for a given provider."""
    provider_lower = provider.lower()

    if provider_lower in ("groq",):
        return GroqProvider.FREE_MODELS.copy()
    elif provider_lower in ("together", "together ai"):
        return TogetherProvider.FREE_MODELS.copy()
    elif provider_lower in ("openrouter",):
        return OpenRouterProvider.list_free_models()
    elif provider_lower in ("fireworks",):
        return FireworksProvider.FREE_MODELS.copy()
    elif provider_lower in ("mistral",):
        return MistralProvider.FREE_MODELS.copy()
    elif provider_lower in ("huggingface", "hf"):
        return HuggingFaceProvider.FREE_MODELS.copy()
    elif provider_lower in ("ollama",):
        # Try to list local models
        try:
            base_url = os.environ.get("OLLAMA_URL", "http://localhost:11434")
            resp = requests.get(f"{base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                return [m["name"] for m in models]
        except Exception:
            pass
        return ["llama3.3", "llama3.1", "codellama", "mistral", "gemma2"]
    elif provider_lower in ("deepinfra",):
        return [DeepInfraProvider.default_model]
    elif provider_lower in ("nous", "nous portal"):
        return [NousPortalProvider.default_model]
    else:
        return []
