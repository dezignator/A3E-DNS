"""Darknet monitoring and IOC extraction — thesis §6.7.2, Table 28.

Processes hourly batches of PCAP metadata captured on darknet address
space (routed but unallocated IP ranges) and extracts indicators of
compromise (IOCs) for the anomaly detector. The processing pipeline is
the one named in Table 28:

    darknet-scan -ioc-update

Table 28 reports 89.5 % of prevented events attributable to this source
during the evaluation period.

The monitor operates on PCAP *metadata*, not on payloads: for each
packet it extracts the 5-tuple, timing, and packet length, and derives
IOCs from scan patterns (many destinations, few sources, unusual
ports). The packet metadata extraction itself is performed by
``scapy`` or ``pyshark`` in the real pipeline; the toy path reads a
JSON metadata fixture.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import numpy as np

from src.intel.stix_parser import IntelRecord

__all__ = [
    "DarknetConfig",
    "DarknetMonitor",
    "DarknetScan",
    "DARKNET_EFFECTIVENESS_PCT",
]

#: Effectiveness reported in Table 28 for the darknet source.
DARKNET_EFFECTIVENESS_PCT: float = 89.5


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class DarknetConfig:
    """Configuration for :class:`DarknetMonitor`.

    Attributes
    ----------
    scan_window_s : float
        Time window over which scan activity is aggregated.
    min_unique_destinations : int
        Minimum number of distinct destinations in a window for the
        activity to be flagged as a scan.
    sample_path : Path
        Local fixture used when the live PCAP pipeline is not configured.
    """

    scan_window_s: float = 3600.0
    min_unique_destinations: int = 32
    sample_path: Path = Path("data/threat_feeds/darknet_pcap_metadata.json")

    def __post_init__(self) -> None:
        if self.scan_window_s <= 0.0:
            raise ValueError(f"scan_window_s must be > 0, got {self.scan_window_s}")
        if self.min_unique_destinations < 1:
            raise ValueError(
                f"min_unique_destinations must be ≥ 1, got {self.min_unique_destinations}"
            )


# --------------------------------------------------------------- scan result
@dataclass(frozen=True)
class DarknetScan:
    """A detected darknet scan."""

    src_ip: str
    unique_destinations: int
    window_start_s: float
    window_end_s: float
    top_dst_ports: tuple[tuple[int, int], ...]
    confidence: float


# --------------------------------------------------------------- monitor
class DarknetMonitor:
    """Darknet scan detection and IOC extraction.

    Parameters
    ----------
    config : DarknetConfig
        Monitor configuration.
    """

    def __init__(self, config: DarknetConfig | None = None) -> None:
        self.config = config or DarknetConfig()

    # --------------------------------------------------------------- API
    def parse_file(self, path: str | Path | None = None) -> list[dict[str, Any]]:
        """Load packet metadata from a JSON fixture or a PCAP-adjacent metadata file."""
        path = Path(path or self.config.sample_path)
        if not path.exists():
            return []
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError:
            return []
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        if isinstance(data, dict) and isinstance(data.get("packets"), list):
            return [d for d in data["packets"] if isinstance(d, dict)]
        return []

    def detect_scans(self, packets: Iterable[dict[str, Any]]) -> list[DarknetScan]:
        """Detect darknet scans from packet metadata.

        Each packet dict must contain at least ``src_ip``, ``dst_ip``,
        ``dst_port`` and ``timestamp`` (epoch seconds).
        """
        by_src: dict[str, list[dict[str, Any]]] = {}
        for pkt in packets:
            src = pkt.get("src_ip")
            if not src:
                continue
            by_src.setdefault(str(src), []).append(pkt)

        scans: list[DarknetScan] = []
        for src, pkts in by_src.items():
            pkts.sort(key=lambda p: float(p.get("timestamp", 0.0)))
            i = 0
            while i < len(pkts):
                t0 = float(pkts[i].get("timestamp", 0.0))
                j = i
                dests: set[str] = set()
                ports: Counter[int] = Counter()
                while j < len(pkts) and float(pkts[j].get("timestamp", 0.0)) - t0 <= self.config.scan_window_s:
                    dst = pkts[j].get("dst_ip")
                    if dst:
                        dests.add(str(dst))
                    try:
                        ports[int(pkts[j].get("dst_port", 0))] += 1
                    except (TypeError, ValueError):
                        pass
                    j += 1
                if len(dests) >= self.config.min_unique_destinations:
                    t1 = float(pkts[j - 1].get("timestamp", t0))
                    scans.append(
                        DarknetScan(
                            src_ip=src,
                            unique_destinations=len(dests),
                            window_start_s=t0,
                            window_end_s=t1,
                            top_dst_ports=tuple(ports.most_common(5)),
                            confidence=min(1.0, len(dests) / (2.0 * self.config.min_unique_destinations)),
                        )
                    )
                i = max(j, i + 1)
        return scans

    def to_intel_records(self, scans: Iterable[DarknetScan]) -> list[IntelRecord]:
        """Convert detected scans into :class:`IntelRecord` IOCs."""
        records: list[IntelRecord] = []
        for scan in scans:
            records.append(
                IntelRecord(
                    source="darknet",
                    indicator_type="ipv4-addr",
                    indicator_value=scan.src_ip,
                    first_seen=None,
                    last_seen=None,
                    confidence=scan.confidence * 100.0,
                    labels=("darknet-scan",),
                    raw={
                        "src_ip": scan.src_ip,
                        "unique_destinations": scan.unique_destinations,
                        "window_start_s": scan.window_start_s,
                        "window_end_s": scan.window_end_s,
                        "top_dst_ports": list(scan.top_dst_ports),
                    },
                )
            )
        return records

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "scan_window_s": self.config.scan_window_s,
            "min_unique_destinations": self.config.min_unique_destinations,
            "effectiveness_pct": DARKNET_EFFECTIVENESS_PCT,
            "interval": "hourly",
        }
