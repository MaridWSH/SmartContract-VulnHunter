import os
from pathlib import Path
from functools import lru_cache
from typing import Any, Dict

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover - fallback for older environments
    import tomli as tomllib  # type: ignore

from pydantic import BaseModel, Field

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic_settings import BaseSettings as BaseSettingsType
else:
    try:
        from pydantic_settings import BaseSettings as BaseSettingsType
    except ImportError:
        from pydantic import BaseSettings as BaseSettingsType

import logging

logger = logging.getLogger(__name__)


def _deep_merge(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two dictionaries, with values from b taking precedence."""
    result = dict(a) if a else {}
    for k, v in (b or {}).items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


class ScanConfig(BaseModel):
    timeout: int = 60  # seconds
    max_retries: int = 3
    threads: int = 4


class ReportConfig(BaseModel):
    format: str = "json"
    output_dir: str = "./reports"


class LLMConfig(BaseModel):
    api_key: str = ""
    model: str = "gpt-4o-mini"
    base_url: str = ""


class AppConfig(BaseSettingsType):
    debug: bool = False
    scan: ScanConfig = Field(default_factory=ScanConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)

    class Config:
        env_prefix = "VULNHUNTER_"
        # Nested env vars: VULNHUNTER__SCAN__TIMEOUT, etc.
        env_nested_delimiter = "__"

    @classmethod
    def defaults(cls) -> "AppConfig":  # helper for tests/consumers
        return cls()


def _read_toml_file(path: Path) -> Dict[str, Any]:
    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
        if isinstance(data, dict) and "vulnhunter" in data:
            return data["vulnhunter"] or {}
        return data or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to read TOML config %s", path)
        return {}


def _load_toml_paths() -> list[Path]:
    paths = []
    # 1) Project root vulnhunter.toml
    paths.append(Path("./vulnhunter.toml"))
    # 2) User config in XDG config dir
    paths.append(Path.home() / ".config" / "vulnhunter.toml")
    return paths


def load_toml_config() -> Dict[str, Any]:
    """Read TOML config files and merge with defaults.
    TOML file is expected to use the root key [vulnhunter] with nested
    sections like [vulnhunter.scan], [vulnhunter.report], etc.
    """
    merged: Dict[str, Any] = {}
    for p in _load_toml_paths():
        if p.exists():
            vulnhunter_cfg = _read_toml_file(p)
            if isinstance(vulnhunter_cfg, dict):
                merged = _deep_merge(merged, vulnhunter_cfg)
    # Ensure we only expose the top-level keys that AppConfig expects
    # The TOML spec in this task is [vulnhunter] and nested sections, so the
    # data here should align with AppConfig fields when loaded.
    return merged


@lru_cache()
def get_config() -> AppConfig:
    """Return a cached AppConfig instance, merging defaults, TOML and env vars."""
    # Start from defaults provided by AppConfig
    base = AppConfig.defaults().dict()
    toml_cfg = load_toml_config() or {}

    # Basic merge: TOML overrides defaults
    merged = _deep_merge(base, toml_cfg)

    # Environment variable overrides
    env_overrides: Dict[str, Any] = {}

    def _set_nested(target: Dict[str, Any], keys: list[str], value: Any) -> None:
        d = target
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value

    def _infer(v: str) -> Any:
        hv = v.strip()
        if hv.lower() in {"true", "false"}:
            return hv.lower() == "true"
        if hv.isdigit() or (hv.startswith("-") and hv[1:].isdigit()):
            try:
                return int(hv)
            except ValueError:
                return hv
        try:
            return float(hv)
        except ValueError:
            return hv

    for name, value in os.environ.items():
        if not name.startswith("VULNHUNTER__"):
            continue
        path = name[len("VULNHUNTER__") :].split("__")
        path = [p.lower() for p in path if p]
        if not path:
            continue
        _set_nested(env_overrides, path, _infer(value))

    if env_overrides:
        merged = _deep_merge(merged, env_overrides)

    return AppConfig(**merged)
