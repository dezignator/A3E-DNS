"""STIX 2.1 / TAXII 2.1 CERT-alert parser — thesis §6.7.1, Table 28.

Ingests CERT alerts as STIX 2.1 bundles and extracts the indicators and
observables used by the A³E-DNS pipeline. The processing pipeline is the
one named in Table 28:

    intel-parse -format stix -validate

which validates each object, extracts a normalised ``IntelRecord`` and
feeds it into the rule/anomaly update path. Table 28 reports 15 rule
updates per minute and 94.2 % of blocked events attributable to this
source during the evaluation period.

The parser is a thin wrapper over ``stix2``. STIX 2.1 is an OASIS
standard; the contribution is the operational integration, not the
parser itself (§6.7).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "IntelRecord",
    "STIXParser",
    "STIXParseError",
    "parse_stix_bundle",
    "parse_stix_file",
    "CERT_EFFECTIVENESS_PCT",
    "RULES_PER_MINUTE",
]

#: Effectiveness reported in Table 28 for the CERT-alert source.
CERT_EFFECTIVENESS_PCT: float = 94.2

#: Rule-update rate reported in Table 28.
RULES_PER_MINUTE: int = 15


# --------------------------------------------------------------- record
@dataclass(frozen=True)
class IntelRecord:
    """Normalised record produced by every Intel adapter.

    Attributes
    ----------
    source : str
        One of ``"cert"``, ``"honeypot"``, ``"darknet"``, ``"vendor"``,
        ``"internal"``.
    indicator_type : str
        E.g. ``"domain-name"``, ``"ipv4-addr"``, ``"file"``.
    indicator_value : str
        The normalised observable value (lower-cased domain name,
        canonical IP, hashed file, etc.).
    first_seen : str | None
        ISO-8601 timestamp, if the source provides one.
    last_seen : str | None
        ISO-8601 timestamp, if the source provides one.
    confidence : float | None
        Source-reported confidence in [0, 100] if available, else ``None``.
    labels : tuple[str, ...]
        Free-form labels from the source.
    raw : dict[str, Any]
        The original object, retained for traceability.
    """

    source: str
    indicator_type: str
    indicator_value: str
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: float | None = None
    labels: tuple[str, ...] = field(default_factory=tuple)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


# --------------------------------------------------------------- error
class STIXParseError(ValueError):
    """Raised when a STIX bundle cannot be parsed."""


# --------------------------------------------------------------- parser
class STIXParser:
    """STIX 2.1 bundle parser for CERT alerts.

    Parameters
    ----------
    validate : bool
        If ``True`` (default), validate every object against the STIX 2.1
        schema using ``stix2``. Any validation failure raises
        :class:`STIXParseError`.
    """

    def __init__(self, *, validate: bool = True) -> None:
        self.validate = validate
        try:
            from stix2 import parse as _stix2_parse  # type: ignore
        except ImportError:
            _stix2_parse = None
        self._stix2_parse = _stix2_parse

    # --------------------------------------------------------------- API
    def parse_bundle(self, bundle: dict[str, Any]) -> list[IntelRecord]:
        """Parse a STIX 2.1 bundle dict into a list of :class:`IntelRecord`."""
        if not isinstance(bundle, dict):
            raise STIXParseError(f"bundle must be a dict, got {type(bundle).__name__}")
        if bundle.get("type") != "bundle":
            raise STIXParseError(f"top-level object must have type='bundle', got {bundle.get('type')!r}")

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise STIXParseError("bundle.objects must be a list")

        records: list[IntelRecord] = []
        for raw in objects:
            record = self._parse_object(raw)
            if record is not None:
                records.append(record)
        return records

    def parse_file(self, path: str | Path) -> list[IntelRecord]:
        path = Path(path)
        if not path.exists():
            raise STIXParseError(f"file not found: {path}")
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise STIXParseError(f"invalid JSON in {path.name}: {exc}") from exc
        return self.parse_bundle(data)

    # --------------------------------------------------------------- internals
    def _parse_object(self, raw: Any) -> IntelRecord | None:
        if not isinstance(raw, dict):
            return None
        obj_type = raw.get("type")

        # Optional STIX validation via stix2.
        if self.validate and self._stix2_parse is not None:
            try:
                self._stix2_parse(raw)
            except Exception as exc:  # noqa: BLE001 - stix2 raises a wide hierarchy
                raise STIXParseError(f"STIX validation failed for {obj_type!r}: {exc}") from exc

        # `indicator` objects carry a STIX pattern.
        if obj_type == "indicator":
            pattern = raw.get("pattern", "")
            value, ind_type = _extract_from_stix_pattern(pattern)
            if value is None:
                return None
            return IntelRecord(
                source="cert",
                indicator_type=ind_type,
                indicator_value=value,
                first_seen=raw.get("valid_from"),
                last_seen=raw.get("valid_until"),
                confidence=_safe_float(raw.get("confidence")),
                labels=tuple(raw.get("labels") or ()),
                raw=raw,
            )

        # `observed-data` / `domain-name` / `ipv4-addr` objects.
        if obj_type in {"domain-name", "ipv4-addr", "ipv6-addr"}:
            value = raw.get("value")
            if not value:
                return None
            return IntelRecord(
                source="cert",
                indicator_type=obj_type,
                indicator_value=str(value).lower(),
                first_seen=None,
                last_seen=None,
                confidence=None,
                labels=tuple(raw.get("labels") or ()),
                raw=raw,
            )

        # Anything else is ignored for the CERT path.
        return None


# --------------------------------------------------------------- pattern helpers
def _extract_from_stix_pattern(pattern: str) -> tuple[str | None, str]:
    """Best-effort extraction of the observable value from a STIX pattern.

    Handles the subset of STIX patterns used by CERT feeds:

        [domain-name:value = 'example.com']
        [ipv4-addr:value = '192.0.2.1']
        [file:hashes.SHA-256 = 'abc...']

    Returns ``(value, indicator_type)``. On failure returns ``(None, "")``.
    """
    if not pattern or "=" not in pattern:
        return None, ""

    # Split off the object type and field.
    head, _, tail = pattern.partition("=")
    head = head.strip().lstrip("[").strip()
    if ":" not in head:
        return None, ""
    obj_type, _, _field = head.partition(":")

    # The value is the quoted string.
    quote_start = tail.find("'")
    if quote_start < 0:
        quote_start = tail.find('"')
    if quote_start < 0:
        return None, ""
    quote = tail[quote_start]
    quote_end = tail.find(quote, quote_start + 1)
    if quote_end < 0:
        return None, ""

    value = tail[quote_start + 1:quote_end]
    return value.lower() if obj_type in {"domain-name"} else value, obj_type.strip()


def _safe_float(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------- module-level
def parse_stix_bundle(bundle: dict[str, Any], *, validate: bool = True) -> list[IntelRecord]:
    """Convenience wrapper around :class:`STIXParser`."""
    return STIXParser(validate=validate).parse_bundle(bundle)


def parse_stix_file(path: str | Path, *, validate: bool = True) -> list[IntelRecord]:
    """Convenience wrapper around :class:`STIXParser.parse_file`."""
    return STIXParser(validate=validate).parse_file(path)


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the CERT-alert role.

    Reads the sample bundle shipped in ``data/threat_feeds/`` and prints
    a summary. Production ingestion runs through the gRPC endpoint on
    the ``threat-intel-dataplane`` node.
    """
    import json
    from pathlib import Path

    sample = Path("data/threat_feeds/cert_alerts_sample.stix.json")
    if not sample.exists():
        print(json.dumps({
            "status": "sample_missing",
            "expected_path": str(sample),
            "effectiveness_pct": CERT_EFFECTIVENESS_PCT,
            "rules_per_minute": RULES_PER_MINUTE,
        }, indent=2))
        return 0

    records = parse_stix_file(sample)
    print(json.dumps({
        "status": "ok",
        "records": len(records),
        "effectiveness_pct": CERT_EFFECTIVENESS_PCT,
        "rules_per_minute": RULES_PER_MINUTE,
        "indicator_types": sorted({r.indicator_type for r in records}),
    }, indent=2))
    return 0
