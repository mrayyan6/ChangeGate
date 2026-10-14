"""LLM provider layer: chat model factory, a hashed response cache and token accounting.

Providers are chosen in config (``llm.provider``): ``ollama`` (local, free) or ``gemini`` (API key from
``.env``). ``fake`` is a scripted model for tests. Responses are cached in SQLite under the SHA-256 of
the serialized prompt and the model parameters (including the bound tools), so reruns are cheap and
reproducible.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Sequence

from langchain_core.caches import BaseCache
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.load import dumps, loads
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult, LLMResult

from changegate.config import Config, secret
from changegate.contracts import TokenUsage


class ProviderNotConfigured(RuntimeError):
    """Raised when the selected provider cannot be used (for example a missing API key)."""


# Response cache

_VOLATILE_KEYS = {"tool_call_id", "response_metadata", "usage_metadata"}


def _strip_volatile(node: Any) -> Any:
    """Drop ids and provider metadata that change between identical calls (string ids only)."""
    if isinstance(node, dict):
        return {
            k: _strip_volatile(v)
            for k, v in node.items()
            if k not in _VOLATILE_KEYS and not (k == "id" and isinstance(v, str))
        }
    if isinstance(node, list):
        return [_strip_volatile(v) for v in node]
    return node


def cache_key(prompt: str, llm_string: str) -> str:
    try:
        normalized = json.dumps(_strip_volatile(json.loads(prompt)), sort_keys=True, separators=(",", ":"))
    except ValueError:
        normalized = prompt
    return hashlib.sha256((normalized + "\0" + llm_string).encode("utf-8")).hexdigest()


class HashedSQLiteCache(BaseCache):
    """LangChain cache keyed by SHA-256(prompt, model parameters). Safe for several processes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), timeout=60, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS llm_cache (key TEXT PRIMARY KEY, value TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP)"
        )
        self._conn.commit()
        self.hits = 0
        self.misses = 0

    def lookup(self, prompt: str, llm_string: str):
        key = cache_key(prompt, llm_string)
        with self._lock:
            row = self._conn.execute("SELECT value FROM llm_cache WHERE key = ?", (key,)).fetchone()
        if row is None:
            self.misses += 1
            return None
        try:
            generations = [loads(item) for item in json.loads(row[0])]
        except Exception:  # an unreadable entry counts as a miss and is overwritten later
            self.misses += 1
            return None
        self.hits += 1
        return generations

    def update(self, prompt: str, llm_string: str, return_val: Sequence[Any]) -> None:
        key = cache_key(prompt, llm_string)
        value = json.dumps([dumps(gen) for gen in return_val])
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO llm_cache (key, value) VALUES (?, ?)", (key, value))
            self._conn.commit()

    def clear(self, **kwargs: Any) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM llm_cache")
            self._conn.commit()


_CACHE: HashedSQLiteCache | None = None


def install_cache(cfg: Config) -> HashedSQLiteCache:
    """Install the process wide LangChain cache (idempotent)."""
    global _CACHE
    from langchain_core.globals import set_llm_cache

    if _CACHE is None or _CACHE.path != cfg.path(cfg.llm.cache_path):
        _CACHE = HashedSQLiteCache(cfg.path(cfg.llm.cache_path))
        set_llm_cache(_CACHE)
    return _CACHE


# Token accounting


class UsageTracker(BaseCallbackHandler):
    """Sums token usage reported by the provider (cached responses keep their original usage)."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.input_tokens = 0
        self.output_tokens = 0
        self.calls = 0

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        self.calls += 1
        for generations in response.generations:
            for gen in generations:
                usage = getattr(getattr(gen, "message", None), "usage_metadata", None) or {}
                self.input_tokens += int(usage.get("input_tokens", 0) or 0)
                self.output_tokens += int(usage.get("output_tokens", 0) or 0)

    def usage(self, cache_hits: int = 0) -> TokenUsage:
        return TokenUsage(
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            total_tokens=self.input_tokens + self.output_tokens,
            llm_calls=self.calls,
            cache_hits=cache_hits,
        )


def cost_usd(cfg: Config, usage: TokenUsage) -> float:
    price = cfg.llm.prices.get(cfg.llm.model)
    if price is None:
        return 0.0
    return round((usage.input_tokens * price.input + usage.output_tokens * price.output) / 1_000_000, 6)


# Chat models


def build_chat_model(cfg: Config) -> BaseChatModel:
    provider = cfg.llm.provider
    if provider == "ollama":
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=cfg.llm.ollama.model,
            base_url=cfg.llm.ollama.base_url,
            temperature=cfg.llm.temperature,
            seed=cfg.run.seed,
            num_ctx=cfg.llm.ollama.num_ctx,
            keep_alive="30m",
            client_kwargs={"timeout": cfg.llm.request_timeout_s},
        )
    if provider == "gemini":
        key = secret(cfg.llm.gemini.api_key_env)
        if not key:
            raise ProviderNotConfigured(
                f"llm.provider is gemini but {cfg.llm.gemini.api_key_env} is not set. Add it to .env "
                "(see .env.example) or run with --provider ollama."
            )
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=cfg.llm.gemini.model,
            google_api_key=key,
            temperature=cfg.llm.temperature,
            max_retries=3,
            timeout=cfg.llm.request_timeout_s,
        )
    if provider == "fake":
        return ScriptedChatModel(script=[])
    raise ProviderNotConfigured(f"unknown llm.provider: {provider}")


class ScriptedChatModel(BaseChatModel):
    """Deterministic stand in for tests: replays a list of AIMessages (or tool call specs) in order."""

    script: list[Any] = []
    position: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any):  # tools are irrelevant to a script
        return self

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None, run_manager=None, **kwargs: Any) -> ChatResult:
        if self.position >= len(self.script):
            message = AIMessage(content="Script finished.")
        else:
            item = self.script[self.position]
            self.position += 1
            if isinstance(item, AIMessage):
                message = item
            else:  # (tool name, args) tuple
                name, args = item
                message = AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"call_{self.position}"}])
        message.usage_metadata = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}
        return ChatResult(generations=[ChatGeneration(message=message)])
