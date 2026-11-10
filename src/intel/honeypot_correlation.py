"""Honeypot telemetry correlation — thesis §6.7.2, Table 28.

Ingests honeypot JSON logs every 5 minutes and correlates them with the
DNS traffic flowing through the A³E-DNS pipeline. The processing
pipeline is the one named in Table 28:

    honeypot-analyze -correlate

The correlation uses spatio-temporal pattern matching: an attacker's
honeypot activity is linked to resolver-side DNS activity within a
bounded time window and a bounded network-distance window. Table 28
reports 96.8 % of detected events attributable to this source during
the evaluation period.

The correlation algorithm is a published spatio-temporal matching
technique (see ``docs/LIMITATIONS.md`` §7.3.6 — the artifact does not
claim a new algorithm).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from src.intel.stix_parser import IntelRecord

__all__ = [
    "HoneypotConfig",
    "HoneypotCorrelator",
    "CorrelationResult",
    "HONEYPOT_EFFECTIVENESS_PCT",
]

#: Effectiveness reported in Table 28 for the honeypot source.
HONEYPOT_EFFECTIVENESS_PCT: float = 96.8


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class HoneypotConfig:
    """Configuration for :class:`HoneypotCorrelator`.

    Attributes
    ----------
    time_window_s : float
        Maximum time between a honeypot event and a DNS event for them
        to be considered correlated.
    network_distance_max : float
        Maximum Euclidean distance in a (network_prefix, port) feature
        space; larger distances break the correlation.
    min_confidence : float
        Correlations below this score are discarded.
    sample_path : Path
        Local fixture used when the live endpoint is not configured.
    """

    time_window_s: float = 300.0
    network_distance_max: float = 16.0
    min_confidence: float = 0.5
    sample_path: Path = Path("data/threat_feeds/honeypot_logs_sample.json")

    def __post_init__(self) -> None:
        if self.time_window_s <= 0.0:
            raise ValueError(f"time_window_s must be > 0, got {self.time_window_s}")
        if self.network_distance_max <= 0.0:
            raise ValueError(f"network_distance_max must be > 0, got {self.network_distance_max}")
        if not (0.0 <= self.min_confidence <= 1.0):
            raise ValueError(f"min_confidence must be in [0, 1], got {self.min_confidence}")


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class CorrelationResult:
    """A correlated honeypot event."""

    honeypot_event: dict[str, Any]
    dns_event: dict[str, Any]
    time_delta_s: float
    network_distance: float
    confidence: float
    score: float


# --------------------------------------------------------------- correlator
class HoneypotCorrelator:
    """Spatio-temporal correlation of honeypot events with DNS events.

    Parameters
    ----------
    config : HoneypotConfig
        Correlator configuration.
    """

    def __init__(self, config: HoneypotConfig | None = None) -> None:
        self.config = config or HoneypotConfig()

    # --------------------------------------------------------------- parse
    def parse_file(self, path: str | Path | None = None) -> list[IntelRecord]:
        """Parse a honeypot JSON log into :class:`IntelRecord` values."""
        path = Path(path or self.config.sample_path)
        if not path.exists():
            return []
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError:
            return []
        events = data if isinstance(data, list) else data.get("events", [])
        records: list[IntelRecord] = []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            value = ev.get("src_ip") or ev.get("dst_ip") or ev.get("domain")
            if value is None:
                continue
            ind_type = "ipv4-addr" if "ip" in (ev.get("src_ip") and "src_ip" or "dst_ip") else "domain-name"
            records.append(
                IntelRecord(
                    source="honeypot",
                    indicator_type=ind_type,
                    indicator_value=str(value).lower(),
                    first_seen=ev.get("timestamp"),
                    last_seen=ev.get("timestamp"),
                    confidence=None,
                    labels=tuple(ev.get("tags") or ()),
                    raw=ev,
                )
            )
        return records

    # --------------------------------------------------------------- correlate
    def correlate(
        self,
        honeypot_events: Iterable[dict[str, Any]],
        dns_events: Iterable[dict[str, Any]],
    ) -> list[CorrelationResult]:
        """Correlate honeypot events with DNS events.

        Both event streams are lists of dicts; each dict must contain:

            * ``timestamp`` (ISO-8601 or epoch seconds),
            * either ``src_ip`` or ``dst_ip`` (or ``domain``),
            * optionally ``port``.

        Returns
        -------
        list[CorrelationResult]
            Sorted by descending score.
        """
        honeypots = [_prepare_event(e) for e in honeypot_events]
        dns = [_prepare_event(e) for e in dns_events]

        results: list[CorrelationResult] = []
        for h in honeypots:
            for d in dns:
                if h["value"] != d["value"]:
                    continue
                dt = abs(h["timestamp"] - d["timestamp"])
                if dt > self.config.time_window_s:
                    continue
                dist = _network_distance(h, d)
                if dist > self.config.network_distance_max:
                    continue
                # Confidence is a monotone decreasing function of both the
                # time gap and the network distance; the exact functional
                # form is an engineering choice (see docs/LIMITATIONS.md).
                time_score = 1.0 - (dt / self.config.time_window_s)
                dist_score = 1.0 - (dist / self.config.network_distance_max)
                confidence = max(0.0, min(1.0, 0.5 * time_score + 0.5 * dist_score))
                if confidence < self.config.min_confidence:
                    continue
                results.append(
                    CorrelationResult(
                        honeypot_event=h["raw"],
                        dns_event=d["raw"],
                        time_delta_s=dt,
                        network_distance=dist,
                        confidence=confidence,
                        score=confidence,
                    )
                )
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "time_window_s": self.config.time_window_s,
            "network_distance_max": self.config.network_distance_max,
            "min_confidence": self.config.min_confidence,
            "effectiveness_pct": HONEYPOT_EFFECTIVENESS_PCT,
            "interval": "5min",
        }


# --------------------------------------------------------------- helpers
def _prepare_event(ev: dict[str, Any]) -> dict[str, Any]:
    value = ev.get("src_ip") or ev.get("dst_ip") or ev.get("domain")
    ts = ev.get("timestamp")
    if isinstance(ts, str):
        try:
            ts_seconds = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            ts_seconds = 0.0
    elif isinstance(ts, (int, float)):
        ts_seconds = float(ts)
    else:
        ts_seconds = 0.0
    return {
        "value": str(value).lower() if value is not None else "",
        "timestamp": ts_seconds,
        "port": float(ev.get("port", 0) or 0),
        "raw": ev,
    }


def _network_distance(a: dict[str, Any], b: dict[str, Any]) -> float:
    """Coarse network distance in (prefix, port) space.

    The distance is ``sqrt(prefix_delta^2 + port_delta^2)`` where
    ``prefix_delta`` is the absolute difference of the first two octets
    of the IPs (0 if not parseable) and ``port_delta`` is the absolute
    difference of the ports, normalised to a comparable scale.
    """
    p = _prefix_octets(a["value"])
    q = _prefix_octets(b["value"])
    prefix_delta = 0.0
    if p is not None and q is not None:
        prefix_delta = abs(int(p[0]) - int(q[0])) + 0.5 * abs(int(p[1]) - int(q[1]))
    port_delta = abs(a["port"] - b["port"]) / 65535.0
    return float(np.sqrt(prefix_delta ** 2 + (port_delta * 16.0) ** 2))


def _prefix_octets(value: str) -> tuple[str, str] | None:
    parts = value.split(".")
    if len(parts) != 4:
        return None
    try:
        int(parts[0]); int(parts[1])
    except ValueError:
        return None
    return parts[0], parts[1]
