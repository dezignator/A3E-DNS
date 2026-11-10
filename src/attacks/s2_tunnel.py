"""S2 — DNS tunneling scenario. Thesis Table 32.

The S2 scenario is a **DNS-over-DNS tunneling** attack that exfiltrates
data via subdomains encoded in normal DNS queries. The tool used in the
thesis is ``dnscat2``; the exact command is reproduced from Table 32.

Command (Table 32)
------------------

    dnscat2-server -listen 0.0.0.0:53 -security=open

Traffic pattern
---------------

    Regular DNS packets of 60 B transmitted at an average rate of
    20 queries per minute.

Detection threshold
-------------------

    Traffic entropy H(X) < 4.2 bits.

Reported performance (Table 32)
-------------------------------

    Success : 99.2 %
    FNR     : 0.8 %
    Response: 1.2 ms

This module produces a deterministic simulation of the tunnel traffic
(``simulate_queries``) and evaluates the entropy test
(``evaluate``).
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "S2Config",
    "S2Result",
    "Dnscat2Command",
    "simulate_queries",
    "evaluate",
    "build_dnscat2_command",
    "run",
    "SUCCESS_RATE",
    "FNR",
    "RESPONSE_MS",
    "THRESHOLD_BITS",
    "PAYLOAD_BYTES",
    "QPM",
]


#: Table 32 values for S2.
SUCCESS_RATE: float = 99.2
FNR: float = 0.8
RESPONSE_MS: float = 1.2
THRESHOLD_BITS: float = 4.2
PAYLOAD_BYTES: int = 60
QPM: int = 20


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class S2Config:
    """Configuration for the S2 simulation.

    Attributes
    ----------
    n_queries : int
        Number of tunnel queries to generate.
    payload_bytes : int
        Payload size per query (60 B in the thesis).
    qpm : int
        Queries per minute (20 in the thesis).
    base_domain : str
        Tunneling base domain.
    seed : int
        Master seed for reproducibility.
    """

    n_queries: int = 500
    payload_bytes: int = PAYLOAD_BYTES
    qpm: int = QPM
    base_domain: str = "test.tunnel"
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n_queries < 10:
            raise ValueError(f"n_queries must be ≥ 10, got {self.n_queries}")
        if self.payload_bytes < 1:
            raise ValueError(f"payload_bytes must be ≥ 1, got {self.payload_bytes}")
        if self.qpm < 1:
            raise ValueError(f"qpm must be ≥ 1, got {self.qpm}")


# --------------------------------------------------------------- command
@dataclass(frozen=True)
class Dnscat2Command:
    """The verbatim dnscat2 command from Table 32."""

    binary: str = "dnscat2-server"
    listen: str = "0.0.0.0:53"
    security: str = "open"

    def argv(self) -> list[str]:
        return [
            self.binary,
            "-listen", self.listen,
            f"-security={self.security}",
        ]

    def __str__(self) -> str:
        return " ".join(self.argv())


def build_dnscat2_command(**kwargs: Any) -> Dnscat2Command:
    return Dnscat2Command(**kwargs)


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class S2Result:
    """Outcome of the S2 evaluation."""

    entropy_bits: float
    threshold_bits: float
    detected: bool
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float
    n_queries: int
    sample_subdomains: tuple[str, ...]


# --------------------------------------------------------------- simulation
def simulate_queries(config: S2Config | None = None) -> list[str]:
    """Generate tunnel subdomains.

    Each subdomain is ``<base64-payload>.<base_domain>``. The payload is
    drawn from ``os.urandom``, so the subdomain labels are close to
    uniformly random — this is what the entropy test looks for.
    """
    cfg = config or S2Config()
    rng = np.random.default_rng(cfg.seed)
    base64_len = ((cfg.payload_bytes + 2) // 3) * 4
    subdomains: list[str] = []
    for _ in range(cfg.n_queries):
        raw = bytes(rng.integers(0, 256, size=cfg.payload_bytes, dtype=np.uint8).tolist())
        encoded = base64.b64encode(raw).decode("ascii")
        subdomains.append(f"{encoded[:base64_len]}.{cfg.base_domain}")
    return subdomains


def _shannon_entropy(labels: str) -> float:
    """Shannon entropy of the character distribution (bits per char)."""
    if not labels:
        return 0.0
    counts: dict[str, int] = {}
    for ch in labels:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(labels))
    return -sum((c / total) * np.log2(c / total) for c in counts.values())


def evaluate(config: S2Config | None = None, *, live: bool = False) -> S2Result:
    """Run the S2 evaluation.

    Parameters
    ----------
    config : S2Config
        Simulation configuration.
    live : bool
        If ``True`` and ``dnscat2-server`` is installed, actually invoke
        the server for a brief window. In the toy and medium modes this
        is always ``False``.
    """
    cfg = config or S2Config()
    subdomains = simulate_queries(cfg)

    # Concatenate the labels and measure the character entropy.
    labels = "".join(s.split(".", 1)[0] for s in subdomains)
    entropy = _shannon_entropy(labels)

    if live and shutil.which("dnscat2-server") is not None:
        cmd = build_dnscat2_command()
        try:
            subprocess.run(cmd.argv(), timeout=2, check=False)
        except (subprocess.SubprocessError, OSError):
            pass

    return S2Result(
        entropy_bits=entropy,
        threshold_bits=THRESHOLD_BITS,
        detected=entropy < THRESHOLD_BITS,
        reported_success_rate=SUCCESS_RATE,
        reported_fnr=FNR,
        reported_response_ms=RESPONSE_MS,
        n_queries=len(subdomains),
        sample_subdomains=tuple(subdomains[:3]),
    )


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for S2."""
    import json
    result = evaluate()
    print(json.dumps({
        "scenario": "S2-Tunnel",
        "command": str(build_dnscat2_command()),
        "entropy_bits": result.entropy_bits,
        "threshold_bits": result.threshold_bits,
        "detected": result.detected,
        "reported_success_rate": result.reported_success_rate,
        "reported_fnr": result.reported_fnr,
        "reported_response_ms": result.reported_response_ms,
        "n_queries": result.n_queries,
        "sample_subdomains": list(result.sample_subdomains),
    }, indent=2))
    return 0
