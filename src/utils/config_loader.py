"""YAML + JSON-schema configuration loader for the A3E-DNS artifact.

The nine YAML files in ``configs/`` are each validated against the
corresponding definition in ``configs/schema.json`` before being returned.
Validation failures raise ``ConfigValidationError`` with a structured
report so that CI can surface the exact JSON-pointer that failed.

Public API
----------
    load_config(name)                -> dict
    load_all_configs()               -> dict[str, dict]
    validate_config(data)            -> None
    CONFIG_NAMES                     -> tuple[str, ...]

Usage
-----
    from src.utils.config_loader import load_config
    aee_cfg = load_config("aee")
    qhe_cfg = load_config("qhe")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

__all__ = [
    "CONFIG_NAMES",
    "CONFIGS_DIR",
    "SCHEMA_PATH",
    "ConfigError",
    "ConfigNotFoundError",
    "ConfigValidationError",
    "load_config",
    "load_all_configs",
    "validate_config",
    "config_path",
    "schema",
]

# --------------------------------------------------------------- locations
# `configs/` lives next to `src/`, i.e. at <repo_root>/configs/.
_REPO_ROOT: Path = Path(__file__).resolve().parents[2]
CONFIGS_DIR: Path = _REPO_ROOT / "configs"
SCHEMA_PATH: Path = CONFIGS_DIR / "schema.json"

CONFIG_NAMES: tuple[str, ...] = (
    "aee",
    "qhe",
    "federated_learning",
    "threat_intel",
    "testbed",
    "p4_pipeline",
    "dask_pipeline",
    "anomaly_detector",
    "amps",
)


# --------------------------------------------------------------- exceptions
class ConfigError(Exception):
    """Base class for all configuration errors."""


class ConfigNotFoundError(ConfigError):
    """Raised when a requested configuration file does not exist."""


class ConfigValidationError(ConfigError):
    """Raised when a configuration fails JSON-schema validation.

    Attributes
    ----------
    path : Path
        The configuration file that failed.
    errors : list[str]
        Human-readable descriptions of each validation failure, each with
        a JSON pointer to the offending location.
    """

    def __init__(self, path: Path, errors: list[str]) -> None:
        self.path = path
        self.errors = list(errors)
        joined = "; ".join(self.errors) if self.errors else "unknown error"
        super().__init__(f"{path.name}: {joined}")


# --------------------------------------------------------------- schema
_SCHEMA_CACHE: dict[str, Any] | None = None


def schema() -> dict[str, Any]:
    """Return the parsed JSON schema (cached after first read)."""
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        if not SCHEMA_PATH.exists():
            raise ConfigNotFoundError(f"schema not found: {SCHEMA_PATH}")
        with SCHEMA_PATH.open("r", encoding="utf-8") as fh:
            _SCHEMA_CACHE = json.load(fh)
    return _SCHEMA_CACHE


def _validator() -> Draft202012Validator:
    return Draft202012Validator(schema())


# --------------------------------------------------------------- paths
def config_path(name: str) -> Path:
    """Return the absolute path to ``configs/<name>.yaml``."""
    if name not in CONFIG_NAMES:
        raise ConfigNotFoundError(
            f"unknown config '{name}'; expected one of {CONFIG_NAMES}"
        )
    return CONFIGS_DIR / f"{name}.yaml"


# --------------------------------------------------------------- validation
def validate_config(data: dict[str, Any]) -> None:
    """Validate ``data`` against the schema; raise on the first error set."""
    errors = sorted(_validator().iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        formatted = [_format_jsonschema_error(e) for e in errors]
        raise ConfigValidationError(Path("<in-memory>"), formatted)


def _format_jsonschema_error(exc: ValidationError) -> str:
    pointer = "/".join(str(p) for p in exc.absolute_path) or "<root>"
    return f"{pointer}: {exc.message}"


# --------------------------------------------------------------- loading
def load_config(name: str) -> dict[str, Any]:
    """Load and validate ``configs/<name>.yaml``.

    Parameters
    ----------
    name : str
        One of ``CONFIG_NAMES``.

    Returns
    -------
    dict
        The parsed YAML contents, validated against ``configs/schema.json``.

    Raises
    ------
    ConfigNotFoundError
        If the file does not exist or ``name`` is unknown.
    ConfigValidationError
        If the YAML fails JSON-schema validation.
    """
    path = config_path(name)
    if not path.exists():
        raise ConfigNotFoundError(f"config not found: {path}")

    with path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigValidationError(path, [f"YAML parse error: {exc}"]) from exc

    if not isinstance(data, dict):
        raise ConfigValidationError(path, ["top-level YAML node must be a mapping"])

    errors = sorted(_validator().iter_errors(data), key=lambda e: list(e.absolute_path))
    if errors:
        raise ConfigValidationError(path, [_format_jsonschema_error(e) for e in errors])

    return data


def load_all_configs() -> dict[str, dict[str, Any]]:
    """Load and validate every configuration file in ``CONFIG_NAMES``."""
    return {name: load_config(name) for name in CONFIG_NAMES}
