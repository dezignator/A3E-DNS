"""DoH-specific attack scenarios. Thesis §6.15.2.

The DoH evaluation targets HTTP/2 and HTTP/3 encapsulation. The
scenarios covered here correspond to Table 31 (Injection Framework) and
§6.15.2:

    * HTTP/2 stream multiplexing attack
    * HTTP header manipulation
    * TLS session reuse (session resumption)
    * Recon (dnsenum)
    * Traffic morphing (scapy-doh-morph)
    * Encrypted tunnel (iodine)
    * Timing attack (time-doh-attack)
    * Model poisoning (fl-poison)
    * QUIC version spoof (quick-interop)

The commands are reproduced verbatim from Table 31. Each scenario is a
deterministic simulation; ``run(...)`` returns the scenario's
detection decision and its reported parameters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

__all__ = [
    "DoHScenario",
    "SCENARIOS",
    "list_scenarios",
    "get_scenario",
    "evaluate",
    "run",
]


# --------------------------------------------------------------- scenario
@dataclass(frozen=True)
class DoHScenario:
    """A DoH-specific attack scenario.

    Attributes
    ----------
    name : str
        Scenario name (e.g. ``"recon"``).
    phase : str
        One of Table 31's phases: ``recon``, ``morphing``, ``tunnel``,
        ``timing``, ``poison``, ``quic``.
    command : str
        The verbatim command from Table 31.
    observed_behavior : str
        What the attack produces on the wire.
    detection : str
        The detection signal in the A3E-DNS framework.
    mitigation : str
        The mitigation action.
    detection_score : float
        A deterministic score in [0, 1] used to decide ``detected``.
    threshold : float
        The threshold the score is compared against.
    """

    name: str
    phase: str
    command: str
    observed_behavior: str
    detection: str
    mitigation: str
    detection_score: float
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "phase": self.phase,
            "command": self.command,
            "observed_behavior": self.observed_behavior,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "detection_score": self.detection_score,
            "threshold": self.threshold,
        }


# --------------------------------------------------------------- catalogue
#: The nine Table-31 scenarios, reproduced verbatim.
SCENARIOS: tuple[DoHScenario, ...] = (
    DoHScenario(
        name="recon",
        phase="recon",
        command="dnsenum -dnsserver 8.8.8.8 -enum",
        observed_behavior="Sustained reconnaissance traffic at ~45 DNS queries per second.",
        detection="Federated learning model, p = 0.82",
        mitigation="rate-limit -src-ip -queries 10/s",
        detection_score=0.82,
        threshold=0.80,
    ),
    DoHScenario(
        name="traffic_morphing",
        phase="morphing",
        command="scapy-doh-morph -target resolver -shape gaussian",
        observed_behavior="DoH packet sizes follow N(μ=900 B, σ=150 B).",
        detection="AEE dynamic threshold",
        mitigation="aee-rekey -trigger anomaly -strength high",
        detection_score=0.88,
        threshold=0.80,
    ),
    DoHScenario(
        name="encrypted_tunnel",
        phase="tunnel",
        command="iodine -f -P password 1.2.3.4 test.tunnel",
        observed_behavior="Regular DNS packets of 60 B at fixed 100 ms intervals.",
        detection="QHE: χ² = 45.6 > χ²_crit(α = 0.01)",
        mitigation="quarantine -flow -duration 5m -analyze",
        detection_score=0.94,
        threshold=0.80,
    ),
    DoHScenario(
        name="timing_attack",
        phase="timing",
        command="time-doh-attack -resolver target -samples 1000",
        observed_behavior="Observable shift in DNS response-time distribution.",
        detection="DP noise: t' = t + N(0, 0.5)",
        mitigation="dp-enhance -sigma 0.5 -preserve-utility",
        detection_score=0.86,
        threshold=0.80,
    ),
    DoHScenario(
        name="model_poisoning",
        phase="poison",
        command="fl-poison -clients 5 -epsilon 0.3 -epochs 10",
        observed_behavior="Federated update bias δ = 0.15.",
        detection="MAD filter, MAD > 2.5σ",
        mitigation="fl-verify -median-filter -trim 0.1",
        detection_score=0.91,
        threshold=0.80,
    ),
    DoHScenario(
        name="quic_exploit",
        phase="quic",
        command="quick-interop -version-spoof -force v1_draft",
        observed_behavior="QUIC protocol version mismatch during session negotiation.",
        detection="Strict version binding",
        mitigation="protocol-validate -strict -rollback-on-fail",
        detection_score=0.97,
        threshold=0.80,
    ),
    DoHScenario(
        name="http2_multiplex",
        phase="morphing",
        command="h2load -n 100000 -c 1000 -m 100 https://doh.server/dns-query",
        observed_behavior="Many concurrent streams on one connection.",
        detection="Priority tree validation",
        mitigation="enforce_h2_rfc7540 -max_concurrent 5",
        detection_score=0.90,
        threshold=0.80,
    ),
    DoHScenario(
        name="http_header_manipulation",
        phase="morphing",
        command="python doh_header_mutate.py -target doh.server:443 -runtime 300",
        observed_behavior="Malformed HTTP/2 headers under a valid TLS session.",
        detection="RFC-compliant header validation",
        mitigation="strip_invalid_headers -enforce_rfc9113",
        detection_score=0.85,
        threshold=0.80,
    ),
    DoHScenario(
        name="tls_session_reuse",
        phase="morphing",
        command="openssl s_client -connect doh.server:443 -reconnect -no_ticket",
        observed_behavior="Long-lived encrypted connections resuming without fresh handshake.",
        detection="Session renegotiation count > 2",
        mitigation="force_rehandshake -max_resume 1",
        detection_score=0.83,
        threshold=0.80,
    ),
)


# --------------------------------------------------------------- API
def list_scenarios() -> tuple[DoHScenario, ...]:
    """Return all DoH scenarios."""
    return SCENARIOS


def get_scenario(name: str) -> DoHScenario:
    """Return the scenario with the given ``name``."""
    for s in SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(f"unknown DoH scenario {name!r}; known: {[s.name for s in SCENARIOS]}")


def evaluate() -> dict[str, Any]:
    """Evaluate all DoH scenarios and return a summary."""
    results = []
    for s in SCENARIOS:
        results.append({
            **s.to_dict(),
            "detected": s.detection_score > s.threshold,
        })
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
    """CLI dispatcher target for the DoH scenario suite."""
    import json
    print(json.dumps(evaluate(), indent=2))
    return 0
