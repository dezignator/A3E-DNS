"""DoT-specific attack scenarios. Thesis §6.15.3.

The DoT evaluation targets TLS 1.3 handshake and session management.
The scenarios are described in §6.15.3:

    * TLS renegotiation attack
    * Certificate validation attack
    * TLS session resumption attack
    * Certificate injection (mitmproxy) — Table 24
    * Padding oracle (PadBuster) — Table 24

The commands for the first three are in §6.15.3; the commands for the
last two are reproduced verbatim from Table 24.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = [
    "DoTScenario",
    "SCENARIOS",
    "list_scenarios",
    "get_scenario",
    "evaluate",
    "run",
]


# --------------------------------------------------------------- scenario
@dataclass(frozen=True)
class DoTScenario:
    """A DoT-specific attack scenario."""

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
SCENARIOS: tuple[DoTScenario, ...] = (
    DoTScenario(
        name="renegotiation",
        command="openssl s_client -connect host:443 -reconnect -no_ticket",
        observed_behavior="Multiple TLS handshakes within one session; renegotiation count > 2.",
        detection="TLS state-machine validation, assert state & transitions",
        mitigation="force_rehandshake -max_resume 1",
        detection_score=0.92,
        threshold=0.80,
    ),
    DoTScenario(
        name="certificate_validation",
        command="sslsplit -D -l /tmp/sslsplit.log 8443 0.0.0.0 443",
        observed_behavior="Inconsistent certificate chain; TLS 1.3 handshake succeeds with warning.",
        detection="SNI / ALPN mismatch, verify(SNI, ALPN) = False",
        mitigation="send_alert(21); close_connection()",
        detection_score=0.96,
        threshold=0.80,
    ),
    DoTScenario(
        name="session_resumption",
        command="openssl s_client -connect host:443 -sess_out /tmp/s -tls1_3",
        observed_behavior="Session ticket reuse; altered session parameters accepted.",
        detection="Session binding violation; assert supported_versions ∩ offered ≠ ∅",
        mitigation="session_binding -strict -rotate-tickets",
        detection_score=0.89,
        threshold=0.80,
    ),
    DoTScenario(
        name="certificate_injection",
        command="mitmproxy -mode transparent -ssl-insecure -set confdir=/mitmproxy",
        observed_behavior="Forged certificate presented under a valid TLS session.",
        detection="SNI / ALPN mismatch, verify(SNI, ALPN) = False",
        mitigation="Immediate termination + alert; send_alert(21); close_connection()",
        detection_score=0.95,
        threshold=0.80,
    ),
    DoTScenario(
        name="padding_oracle",
        command="ruby padbuster.rb https://doh.server/encrypted AAAAA 8 -encoding 1",
        observed_behavior="Distinct error responses distinguish padding-valid from padding-invalid ciphertexts.",
        detection="Homomorphic ciphertext re-randomization; detect_padding = HE.eval(c1 = c2)",
        mitigation="C' = C ⊕ H(noise || timestamp)",
        detection_score=0.90,
        threshold=0.80,
    ),
)


# --------------------------------------------------------------- API
def list_scenarios() -> tuple[DoTScenario, ...]:
    return SCENARIOS


def get_scenario(name: str) -> DoTScenario:
    for s in SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(f"unknown DoT scenario {name!r}; known: {[s.name for s in SCENARIOS]}")


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
