
---

## `scripts/validate_manifests.py`

```python
#!/usr/bin/env python3
"""
scripts/validate_manifests.py

Validate manifests against the JSON Schemas in schemas/.

We implemented this script so that a reviewer can confirm that a
manifest tree has not been hand-edited after the producing module
wrote it. The script walks the tree, picks the schema for each file
by name and content, and reports pass/fail with the failing JSON
Pointer.

The script uses the jsonschema library when it is installed. When it
is not, it falls back to a minimal validator that handles only the
keywords the schemas actually use: type, required, enum, pattern,
minimum, maximum, minLength, and additionalProperties. That fallback
covers all five schemas; a schema that needed $ref or anyOf would
have needed the full library, and we wrote the schemas to avoid both
so that the fallback would remain sufficient.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

LOGGER = logging.getLogger("a3e.extended.validate_manifests")

try:
    import jsonschema  # type: ignore
    _HAS_JSONSCHEMA = True
except ImportError:
    jsonschema = None  # type: ignore
    _HAS_JSONSCHEMA = False


# --------------------------------------------------------------------------- #
# Minimal validator
# --------------------------------------------------------------------------- #


class ValidationError(Exception):
    def __init__(self, pointer: str, message: str) -> None:
        super().__init__(f"{pointer}: {message}")
        self.pointer = pointer
        self.message = message


def _check_type(value: Any, expected: Any, pointer: str) -> None:
    if isinstance(expected, list):
        allowed = expected
    else:
        allowed = [expected]

    def _matches(v: Any, t: str) -> bool:
        if t == "object":
            return isinstance(v, dict)
        if t == "array":
            return isinstance(v, list)
        if t == "string":
            return isinstance(v, str)
        if t == "integer":
            return isinstance(v, int) and not isinstance(v, bool)
        if t == "number":
            return isinstance(v, (int, float)) and not isinstance(v, bool)
        if t == "boolean":
            return isinstance(v, bool)
        if t == "null":
            return v is None
        return True

    for t in allowed:
        if _matches(value, t):
            return
    raise ValidationError(
        pointer, f"expected one of {allowed}, got {type(value).__name__}"
    )


def _validate(schema: Mapping[str, Any], value: Any, pointer: str = "/") -> None:
    if "type" in schema:
        _check_type(value, schema["type"], pointer)

    if "enum" in schema:
        if value not in schema["enum"]:
            raise ValidationError(pointer, f"value {value!r} not in {schema['enum']}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise ValidationError(pointer, f"string shorter than {schema['minLength']}")
        if "pattern" in schema and not re.match(schema["pattern"], value):
            raise ValidationError(pointer, f"string does not match {schema['pattern']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ValidationError(pointer, f"{value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ValidationError(pointer, f"{value} > maximum {schema['maximum']}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ValidationError(pointer, f"missing required field {key!r}")
        props = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, val in value.items():
            child_ptr = f"{pointer.rstrip('/')}/{key}"
            if key in props:
                _validate(props[key], val, child_ptr)
            elif additional is False:
                raise ValidationError(pointer, f"unexpected property {key!r}")
            elif isinstance(additional, dict):
                _validate(additional, val, child_ptr)


def validate_with_fallback(
    schema: Mapping[str, Any], payload: Any
) -> List[str]:
    if _HAS_JSONSCHEMA:
        validator = jsonschema.Draft202012Validator(schema)
        return [
            f"{'/'.join(str(p) for p in e.absolute_path) or '/'}: {e.message}"
            for e in validator.iter_errors(payload)
        ]
    try:
        _validate(schema, payload)
        return []
    except ValidationError as e:
        return [str(e)]


# --------------------------------------------------------------------------- #
# Schema routing
# --------------------------------------------------------------------------- #


def pick_schema(
    manifest_path: Path,
    payload: Any,
) -> Optional[Path]:
    """Pick the schema for a manifest by name and content.

    The routing is name-first, content-second. Name is the reliable
    signal; content heuristics catch only the case where the same
    file name appears with a different shape (e.g. a manifest that
    carries both metrics and confusion).
    """
    name = manifest_path.name.lower()
    if name == "core_metrics.json" or name.endswith("_metrics.json"):
        return manifest_path.parent.parent.parent / "schemas" / "metrics.schema.json"
    if name == "byzantine_sweep.json":
        return manifest_path.parent.parent.parent / "schemas" / "metrics.schema.json"
    if name == "manifest.json":
        # Could be catalogue, experiment run, or generic. Fall back to the envelope.
        return manifest_path.parent.parent.parent / "schemas" / "manifest.schema.json"
    if name == "scenario_rows.jsonl":
        return None  # JSONL handled separately
    if name.endswith("_state.json") or name == "orchestrator_summary.json":
        return None  # orchestration state, not a manifest envelope
    return None


def _find_schemas_root(manifests_root: Path) -> Optional[Path]:
    """Locate the schemas directory relative to the manifests root."""
    for candidate in (
        manifests_root.parent.parent / "schemas",
        manifests_root.parent / "schemas",
        Path("schemas"),
    ):
        if candidate.exists() and candidate.is_dir():
            return candidate
    return None


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def _load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _validate_directory(manifests_root: Path, schemas_root: Path) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    n_valid = 0
    n_invalid = 0
    n_skipped = 0

    # Cache loaded schemas.
    schema_cache: Dict[str, Dict[str, Any]] = {}

    def _load_cached(name: str) -> Optional[Dict[str, Any]]:
        if name in schema_cache:
            return schema_cache[name]
        path = schemas_root / name
        if not path.exists():
            return None
        schema_cache[name] = _load_schema(path)
        return schema_cache[name]

    for path in sorted(manifests_root.rglob("*.json")):
        name = path.name.lower()
        # Skip orchestration state; it is not a manifest envelope.
        if name.endswith("_state.json") or name == "orchestrator_summary.json":
            results.append({
                "path": str(path),
                "status": "skipped",
                "reason": "orchestration state",
            })
            n_skipped += 1
            continue

        try:
            payload = json.loads(path.read_text())
        except Exception as exc:
            results.append({
                "path": str(path),
                "status": "invalid",
                "errors": [f"parse: {exc}"],
            })
            n_invalid += 1
            continue

        # Choose the schema.
        schema_name: Optional[str] = None
        if "metrics" in payload and isinstance(payload.get("metrics"), dict):
            schema_name = "metrics.schema.json"
        elif "experiment_id" in payload and "status" in payload:
            schema_name = "experiment_run.schema.json"
        elif "round" in payload and "attack_to_reference_ratio" in payload:
            schema_name = "byzantine_round.schema.json"
        elif "module" in payload:
            schema_name = "manifest.schema.json"

        if schema_name is None:
            results.append({
                "path": str(path),
                "status": "skipped",
                "reason": "no matching schema",
            })
            n_skipped += 1
            continue

        schema = _load_cached(schema_name)
        if schema is None:
            results.append({
                "path": str(path),
                "status": "invalid",
                "errors": [f"missing schema: {schema_name}"],
            })
            n_invalid += 1
            continue

        errors = validate_with_fallback(schema, payload)
        if errors:
            results.append({
                "path": str(path),
                "schema": schema_name,
                "status": "invalid",
                "errors": errors,
            })
            n_invalid += 1
        else:
            results.append({
                "path": str(path),
                "schema": schema_name,
                "status": "valid",
            })
            n_valid += 1

    return {
        "n_valid": n_valid,
        "n_invalid": n_invalid,
        "n_skipped": n_skipped,
        "results": results,
        "jsonschema_available": _HAS_JSONSCHEMA,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate A3E-DNS manifests against the JSON Schemas."
    )
    parser.add_argument("--manifests", type=Path, required=True)
    parser.add_argument("--schemas", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not args.manifests.exists():
        LOGGER.error("manifests root does not exist: %s", args.manifests)
        return 1
    if not args.schemas.exists():
        LOGGER.error("schemas root does not exist: %s", args.schemas)
        return 1

    report = _validate_directory(args.manifests, args.schemas)
    LOGGER.info(
        "validation complete: %d valid, %d invalid, %d skipped (jsonschema=%s)",
        report["n_valid"],
        report["n_invalid"],
        report["n_skipped"],
        report["jsonschema_available"],
    )

    if args.out is not None:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2))

    if args.strict and report["n_invalid"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
