"""Configuration loading for ChangeGate.

Settings come from ``config/default.yaml`` (or a file passed on the command line), then from dotted
overrides such as ``llm.provider=gemini``. Secrets are only read from the environment, which is filled
from ``.env`` by python-dotenv. Relative paths are resolved against the repository root.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / "config" / "default.yaml"

GuardKind = Literal["none", "trivy", "opa", "agentspec"]
FeedbackMode = Literal["none", "bare", "reason", "hint", "native"]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunConfig(_Section):
    seed: int = 7
    max_steps: int = 20
    work_dir: str = "work"
    results_dir: str = "results"
    scenarios_dir: str = "scenarios/phase1"


class OllamaConfig(_Section):
    model: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434"
    num_ctx: int = 16384


class GeminiConfig(_Section):
    model: str = "gemini-3.8-flash"
    api_key_env: str = "GEMINI_API_KEY"


class Price(_Section):
    input: float = 0.0
    output: float = 0.0


class LLMConfig(_Section):
    provider: Literal["ollama", "gemini", "fake"] = "ollama"
    temperature: float = 0.0
    cache_path: str = ".cache/llm_cache.sqlite"
    request_timeout_s: int = 300
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    prices: dict[str, Price] = Field(default_factory=dict)

    @property
    def model(self) -> str:
        if self.provider == "gemini":
            return self.gemini.model
        if self.provider == "ollama":
            return self.ollama.model
        return "fake"


class TerraformConfig(_Section):
    binary: str = "terraform"
    env_dir: str = "envs/fintech"
    data_dir: str = "envs/fintech/.terraform"
    plugin_cache_dir: str = ".terraform-plugin-cache"
    plan_cache_dir: str = ".cache/plans"
    timeout_s: int = 240


class OpaConfig(_Section):
    binary: str = "opa"
    mode: Literal["eval", "server"] = "eval"
    policy_dir: str = "policies"
    query: str = "data.changegate.main.decision"
    server_url: str = "http://127.0.0.1:8181"
    timeout_s: int = 30


class TrivyConfig(_Section):
    binary: str = "trivy"
    severities: list[str] = Field(default_factory=lambda: ["HIGH", "CRITICAL"])
    timeout_s: int = 180


class AgentConfig(_Section):
    id: str = "changegate-agent"


class ArmConfig(_Section):
    guard: GuardKind
    feedback: FeedbackMode


class Config(_Section):
    run: RunConfig = Field(default_factory=RunConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    terraform: TerraformConfig = Field(default_factory=TerraformConfig)
    opa: OpaConfig = Field(default_factory=OpaConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    arms: dict[str, ArmConfig] = Field(default_factory=dict)

    def path(self, relative: str | Path) -> Path:
        """Resolve a configured path against the repository root."""
        p = Path(relative)
        return p if p.is_absolute() else REPO_ROOT / p

    def arm(self, name: str) -> ArmConfig:
        if name not in self.arms:
            known = ", ".join(sorted(self.arms))
            raise KeyError(f"unknown arm '{name}', known arms: {known}")
        return self.arms[name]


def _set_dotted(data: dict[str, Any], dotted: str, value: Any) -> None:
    keys = dotted.split(".")
    node = data
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    node[keys[-1]] = value


def parse_override(text: str) -> tuple[str, Any]:
    """Parse ``a.b=value``; the value is read as YAML so numbers and booleans keep their type."""
    if "=" not in text:
        raise ValueError(f"override '{text}' must look like key.path=value")
    key, raw = text.split("=", 1)
    return key.strip(), yaml.safe_load(raw)


def load_config(path: str | Path | None = None, overrides: list[str] | None = None) -> Config:
    """Load the YAML config, apply dotted overrides and load ``.env`` into the environment."""
    load_dotenv(REPO_ROOT / ".env", override=False)
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    data: dict[str, Any] = {}
    if cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    for item in overrides or []:
        key, value = parse_override(item)
        _set_dotted(data, key, value)
    return Config.model_validate(data)


def secret(name: str) -> str | None:
    """Read a secret from the environment. Callers must never print the value."""
    value = os.environ.get(name, "").strip()
    return value or None
