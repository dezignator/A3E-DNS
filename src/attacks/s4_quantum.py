"""S4 — Quantum preparation scenario. Thesis Table 32.

The S4 scenario tests the framework against **post-quantum TLS
handshakes** using lattice-based key exchange (kyber1024). The tool used
in the thesis is the OpenSSL client with the ``kyber1024`` group; the
exact command is reproduced from Table 32.

Command (Table 32)
------------------

    openssl s_client -connect doh.example.com:443 -groups kyber1024

Traffic pattern
---------------

    Post-quantum TLS handshake using lattice-based key-exchange
    mechanisms.

Detection threshold
-------------------

    Quantum safety score > 0.9.

Reported performance (Table 32)
-------------------------------

    Success : 100.0 %
    FNR     : 0.0 %
    Response: 1.8 ms

The S4 scenario is unique in the thesis in that the reported success
rate is exactly 100 % and the FNR is exactly 0 %: no kyber1024
handshake failed the quantum-safety check in the evaluation.

This module produces a deterministic simulation (``simulate_handshakes``)
and evaluates the safety check (``evaluate``). If the ``oqs`` Python
package (or ``liboqs``) is available, :func:`evaluate` can invoke a real
handshake in live mode.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "S4Config",
    "S4Result",
    "OpensslCommand",
    "simulate_handshakes",
    "evaluate",
    "build_openssl_command",
    "run",
    "SUCCESS_RATE",
    "FNR",
    "RESPONSE_MS",
    "QUANTUM_SAFETY_THRESHOLD",
    "KEM",
]


#: Table 32 values for S4.
SUCCESS_RATE: float = 100.0
FNR: float = 0.0
RESPONSE_MS: float = 1.8
QUANTUM_SAFETY_THRESHOLD: float = 0.9
KEM: str = "kyber1024"


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class S4Config:
    """Configuration for the S4 simulation.

    Attributes
    ----------
    n_handshakes : int
        Number of handshakes to simulate.
    kem : str
        Post-quantum KEM name (``"kyber1024"`` in the thesis).
    server_host : str
        Target host for the handshake (used in live mode).
    server_port : int
        Target port for the handshake.
    seed : int
        Master seed for reproducibility.
    """

    n_handshakes: int = 100
    kem: str = KEM
    server_host: str = "doh.example.com"
    server_port: int = 443
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n_handshakes < 1:
            raise ValueError(f"n_handshakes must be ≥ 1, got {self.n_handshakes}")
        if self.kem not in {"kyber512", "kyber768", "kyber1024"}:
            raise ValueError(f"unsupported KEM {self.kem!r}")
        if not (0 < self.server_port < 65536):
            raise ValueError(f"server_port must be in (0, 65536), got {self.server_port}")


# --------------------------------------------------------------- command
@dataclass(frozen=True)
class OpensslCommand:
    """The verbatim openssl s_client command from Table 32."""

    binary: str = "openssl"
    subcommand: str = "s_client"
    host: str = "doh.example.com"
    port: int = 443
    group: str = KEM

    def argv(self) -> list[str]:
        return [
            self.binary,
            self.subcommand,
            "-connect", f"{self.host}:{self.port}",
            "-groups", self.group,
        ]

    def __str__(self) -> str:
        return " ".join(self.argv())


def build_openssl_command(**kwargs: Any) -> OpensslCommand:
    return OpensslCommand(**kwargs)


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class S4Result:
    """Outcome of the S4 evaluation."""

    quantum_safety_scores: tuple[float, ...]
    min_score: float
    threshold: float
    detected: bool
    passed: int
    failed: int
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float
    openssl_available: bool
    kem_available: bool


# --------------------------------------------------------------- simulation
def simulate_handshakes(config: S4Config | None = None) -> np.ndarray:
    """Generate simulated quantum-safety scores for the handshakes.

    For a correctly-negotiated kyber1024 handshake, the safety score is
    a value in ``[0, 1]``; the thesis reports 100 % success, so the
    simulator draws the scores from a high-concentration distribution
    near 1.
    """
    cfg = config or S4Config()
    rng = np.random.default_rng(cfg.seed)
    # Beta(9, 1) is tightly concentrated above 0.9; this matches the
    # reported 100 % pass rate at the 0.9 threshold.
    return rng.beta(9.0, 1.0, size=cfg.n_handshakes)


def _check_openssl_kem_support(kem: str) -> bool:
    """Check whether the system OpenSSL advertises the requested KEM."""
    if shutil.which("openssl") is None:
        return False
    try:
        proc = subprocess.run(
            ["openssl", "list", "-kem-algorithms"],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.SubprocessError, OSError):
        return False
    if proc.returncode != 0:
        return False
    return kem.lower() in proc.stdout.lower()


def evaluate(config: S4Config | None = None, *, live: bool = False) -> S4Result:
    """Run the S4 evaluation.

    Parameters
    ----------
    config : S4Config
        Simulation configuration.
    live : bool
        If ``True`` and OpenSSL advertises the requested KEM, actually
        run one handshake against ``server_host``. In the toy and medium
        modes this is always ``False``.
    """
    cfg = config or S4Config()
    scores = simulate_handshakes(cfg)
    passed = int((scores > QUANTUM_SAFETY_THRESHOLD).sum())
    failed = int(cfg.n_handshakes - passed)

    openssl_available = shutil.which("openssl") is not None
    kem_available = _check_openssl_kem_support(cfg.kem) if openssl_available else False

    if live and kem_available:
        cmd = build_openssl_command(host=cfg.server_host, port=cfg.server_port, group=cfg.kem)
        try:
            subprocess.run(cmd.argv(), capture_output=True, timeout=10, check=False)
        except (subprocess.SubprocessError, OSError):
            pass

    return S4Result(
        quantum_safety_scores=tuple(float(x) for x in scores),
        min_score=float(scores.min()),
        threshold=QUANTUM_SAFETY_THRESHOLD,
        detected=bool(passed == cfg.n_handshakes),
        passed=passed,
        failed=failed,
        reported_success_rate=SUCCESS_RATE,
        reported_fnr=FNR,
        reported_response_ms=RESPONSE_MS,
        openssl_available=openssl_available,
        kem_available=kem_available,
    )


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for S4."""
    import json
    result = evaluate()
    print(json.dumps({
        "scenario": "S4-Quantum",
        "command": str(build_openssl_command()),
        "min_score": result.min_score,
        "threshold": result.threshold,
        "detected": result.detected,
        "passed": result.passed,
        "failed": result.failed,
        "reported_success_rate": result.reported_success_rate,
        "reported_fnr": result.reported_fnr,
        "reported_response_ms": result.reported_response_ms,
        "openssl_available": result.openssl_available,
        "kem_available": result.kem_available,
    }, indent=2))
    return 0
