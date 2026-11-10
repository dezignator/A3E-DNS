"""Vendor threat-feed normaliser — thesis §6.7.3, Table 28.

Ingests commercial vendor feeds in CSV or JSON and normalises them into
the common :class:`IntelRecord` schema. The processing pipeline is the
one named in Table 28:

    vendor-intel -normalize -merge

Vendor feeds are weighted by a per-vendor reputation score, which is
updated online from the vendor's historical accuracy (§6.7.3). Table 28
reports 92.1 % of protected events attributable to this source during
the evaluation period.

The normalisation itself is a standard data-engineering task; the
contribution of this module is the operational integration, not the
normalisation (§6.7).
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "VendorFeedConfig",
    "VendorFeedNormalizer",
    "VENDOR_EFFECTIVENESS_PCT",
]

#: Effectiveness reported in Table 28 for the vendor source.
VENDOR_EFFECTIVENESS_PCT: float = 92.1


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class VendorFeedConfig:
    """Configuration for :class:`VendorFeedNormalizer`.

    Attributes
    ----------
    reputation_prior : float
        Initial reputation score for each vendor in [0, 1].
    reputation_decay : float
        Exponential decay applied to the prior on each observation
        (0 = fully trust the prior; 1 = fully trust the observation).
    sample_path : Path
        Local fixture used when the live feed endpoint is not configured.
    """

    reputation_prior: float = 0.5
    reputation_decay: float = 0.1
    sample_path: Path = Path("data/threat_feeds/vendor_feeds_normalized.json")

    def __post_init__(self) -> None:
        if not (0.0 <= self.reputation_prior <= 1.0):
            raise ValueError(f"reputation_prior must be in [0, 1], got {self.reputation_prior}")
        if not (0.0 <= self.reputation_decay <= 1.0):
            raise ValueError(f"reputation_decay must be in [0, 1], got {self.reputation_decay}")


# --------------------------------------------------------------- normalizer
class VendorFeedNormalizer:
    """Normalise vendor CSV / JSON feeds into :class:`IntelRecord` values.

    Parameters
    ----------
    config : VendorFeedConfig
        Normaliser configuration.
    """

    def __init__(self, config: VendorFeedConfig | None = None) -> None:
        self.config = config or VendorFeedConfig()
        self._reputation: dict[str, float] = {}

    # --------------------------------------------------------------- API
    def reputation_of(self, vendor: str) -> float:
        """Return the current reputation score of ``vendor``."""
        return self._reputation.get(vendor, self.config.reputation_prior)

    def update_reputation(self, vendor: str, observed_accuracy: float) -> float:
        """Update the reputation score with ``observed_accuracy``.

        ``observed_accuracy`` must be in [0, 1]. The update is the
        standard exponential smoothing with ``reputation_decay``.
        """
        if not (0.0 <= observed_accuracy <= 1.0):
            raise ValueError(f"observed_accuracy must be in [0, 1], got {observed_accuracy}")
        prior = self.reputation_of(vendor)
        decay = self.config.reputation_decay
        new = (1.0 - decay) * prior + decay * observed_accuracy
        self._reputation[vendor] = float(new)
        return new

    def parse_json(self, data: list[dict[str, Any]] | dict[str, Any]) -> list[IntelRecord]:
        """Parse a vendor JSON feed."""
        if isinstance(data, dict):
            entries = data.get("entries") or data.get("indicators") or []
        else:
            entries = data
        records: list[IntelRecord] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            record = self._from_dict(entry)
            if record is not None:
                records.append(record)
        return records

    def parse_csv(self, text: str) -> list[IntelRecord]:
        """Parse a vendor CSV feed. Expects headers ``value`` and ``type``."""
        reader = csv.DictReader(io.StringIO(text))
        records: list[IntelRecord] = []
        for row in reader:
            record = self._from_dict(row)
            if record is not None:
                records.append(record)
        return records

    def parse_file(self, path: str | Path | None = None) -> list[IntelRecord]:
        """Parse a vendor feed from disk, inferring the format from the extension."""
        path = Path(path or self.config.sample_path)
        if not path.exists():
            return []
        if path.suffix.lower() == ".csv":
            return self.parse_csv(path.read_text(encoding="utf-8"))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return self.parse_json(data)
        return self.parse_json(data)

    # --------------------------------------------------------------- internals
    def _from_dict(self, entry: dict[str, Any]) -> IntelRecord | None:
        value = entry.get("value") or entry.get("indicator") or entry.get("observable")
        if value is None:
            return None
        ind_type = entry.get("type") or "domain-name"
        vendor = str(entry.get("vendor") or "unknown")
        confidence = _safe_float(entry.get("confidence"))
        reputation = self.reputation_of(vendor)
        weighted_confidence = None if confidence is None else confidence * reputation
        return IntelRecord(
            source="vendor",
            indicator_type=str(ind_type),
            indicator_value=str(value).lower(),
            first_seen=entry.get("first_seen"),
            last_seen=entry.get("last_seen"),
            confidence=weighted_confidence,
            labels=tuple(entry.get("labels") or ()),
            raw=entry,
        )

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "reputation_prior": self.config.reputation_prior,
            "reputation_decay": self.config.reputation_decay,
            "vendors": dict(self._reputation),
            "effectiveness_pct": VENDOR_EFFECTIVENESS_PCT,
            "interval": "daily",
        }


def _safe_float(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None
