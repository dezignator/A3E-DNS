"""DoQ-specific attack scenarios. Thesis §6.15.4, Table 22, Table 24.

The DoQ evaluation targets QUIC v1 mobility, stream multiplexing, and
congestion-control dynamics. Scenarios covered here:

    * connection migration attack
    * stream multiplexing attack
    * version negotiation attack
    * QUIC congestion exploit (quic-flood) — Table 22
    * QUIC reflection (quic-attack) — Table 23
    * QUIC version downgrade — Table 22

The commands are reproduced verbatim from Tables 22–24.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "DoQScenario",
    "SCENARIOS",
    "list_scenarios",
    "get_scenario",
    "evaluate",
    "run",
]


# --------------------------------------------------------------- scenario
@dataclass(frozen=True)
class DoQScenario:
    """A DoQ-specific attack scenario."""

    name: str
    command: str
    observed_behavior: str
    detection: str
    mitigation: str
    detection_score: float
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "observed_behavior": self.observed_behavior,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "detection_score": self.detection_score,
            "threshold": self.threshold,
        }


# --------------------------------------------------------------- catalogue
SCENARIOS: tuple[DoQScenario, ...] = (
    DoQScenario(
        name="connection_migration",
        command="python3 doq_migrate.py -target 10.0.0.1 -cid rotate -interval 5",
        observed_behavior="Connection ID rotation under modified client addresses.",
        detection="CID allocation rate > 100/s; require_connection_id_rotation",
        mitigation="limit_cid_issuance -rate 10/s",
        detection_score=0.88,
        threshold=0.80,
    ),
    DoQScenario(
        name="stream_multiplexing",
        command="python3 doq_mux.py -target 10.0.0.1 -streams 256 -pattern burst",
        observed_behavior="Many concurrent streams carrying malicious payloads.",
        detection="Stream count exceeds per-flow baseline; stream-level anomaly",
        mitigation="stream_policing -max_concurrent 16",
        detection_score=0.91,
        threshold=0.80,
    ),
    DoQScenario(
        name="version_negotiation",
        command="python3 doq_ver.py -target 10.0.0.1 -offer 0x00000000 -spoof",
        observed_behavior="Forced negotiation towards legacy / insecure versions.",
        detection="Version consistency: assert supported_versions ∩ offered ≠ ∅",
        mitigation="send_connection_close(0x010C); log_attack(version_downgrade)",
        detection_score=0.93,
        threshold=0.80,
    ),
    DoQScenario(
        name="quic_congestion_exploit",
        command="python3 quic-flood.py -target 10.0.0.1 -pps 50000 -spin-bit 1 -version 0x00000001",
        observed_behavior="Congestion window growth rate > threshold; user QoS degraded.",
        detection="DoQ-aware congestion analysis: cwnd_growth_rate > 3σ",
        mitigation="rate_limit = baseline × (1 − attack_ratio²)",
        detection_score=0.92,
        threshold=0.80,
    ),
    DoQScenario(
        name="quic_reflection",
        command="./quic_attack -reflect -amplify 50 -threads 16",
        observed_behavior="Amplification factor > 1; response size > query size.",
        detection="Response size / query size ratio; source port consistency",
        mitigation="rate_limit -src-ip -qps 100",
        detection_score=0.89,
        threshold=0.80,
    ),
    DoQScenario(
        name="quic_version_downgrade",
        command="python3 doq_ver.py -target 10.0.0.1 -force 0x00000000",
        observed_behavior="Downgraded to a version other than QUIC v1.",
        detection="Strict version binding, rollback on fail",
        mitigation="protocol-validate -strict -rollback-on-fail",
        detection_score=0.94,
        threshold=0.80,
    ),
)


# --------------------------------------------------------------- API
def list_scenarios() -> tuple[DoQScenario, ...]:
    return SCENARIOS


def get_scenario(name: str) -> DoQScenario:
    for s in SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(f"unknown DoQ scenario {name!r}; known: {[s.name for s in SCENARIOS]}")


def evaluate() -> dict[str, Any]:
    results = [
        {**s.to_dict(), "detected": s.detection_score > s.threshold}
        for s in SCENARIOS
    ]
    n_total = len(results)
    n_detected = sum(1 for r in results if r["detected"])
    return {
        "n_scenarios": n_total,
        "n_detected": n_detected,
        "detection_rate": float(n_detected / n_total) if n_total else 0.0,
        "scenarios": results,
    }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    import json
    print(json.dumps(evaluate(), indent=2))
    return 0
