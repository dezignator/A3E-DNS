"""S1 — Timing attack scenario. Thesis Table 32.

The S1 scenario is a **traffic-analysis / timing-inference** attack that
recovers information from inter-arrival time (IAT) distributions of DoH
traffic. The tool used in the thesis is ``tshark`` with a custom
command; the exact command is reproduced below from Table 32.

Command (Table 32)
------------------

    tshark -r capture.pcap -Y "dns.time > 0.1" -T fields -e frame.time_delta

Traffic pattern
---------------

    Inter-arrival time distribution exhibits right-skewed deviation
    under timing inference attempts.

Detection threshold
-------------------

    D_KL(P || Q) > 0.30

Reported performance (Table 32)
-------------------------------

    Success : 98.7 %
    FNR     : 1.3 %
    Response: 0.4 ms

This module produces a deterministic simulation of the attack:
``simulate_iat(...)`` generates right-skewed IAT samples, and
``evaluate(...)`` computes the KL divergence of those samples against a
benign baseline and returns the S1 decision.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "S1Config",
    "S1Result",
    "TsharkCommand",
    "simulate_iat",
    "evaluate",
    "build_tshark_command",
    "run",
    "SUCCESS_RATE",
    "FNR",
    "RESPONSE_MS",
    "THRESHOLD",
]


#: Table 32 values for S1.
SUCCESS_RATE: float = 98.7
FNR: float = 1.3
RESPONSE_MS: float = 0.4
THRESHOLD: float = 0.30


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class S1Config:
    """Configuration for the S1 simulation.

    Attributes
    ----------
    n_samples : int
        Number of IAT samples to generate.
    benign_mean_ms : float
        Mean of the benign IAT distribution.
    benign_std_ms : float
        Standard deviation of the benign IAT distribution.
    attack_scale : float
        Right-skew scale for the attack samples (higher = more skewed).
    seed : int
        Master seed for reproducibility.
    """

    n_samples: int = 1000
    benign_mean_ms: float = 20.0
    benign_std_ms: float = 5.0
    attack_scale: float = 3.0
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n_samples < 10:
            raise ValueError(f"n_samples must be ≥ 10, got {self.n_samples}")
        if self.benign_mean_ms <= 0.0:
            raise ValueError(f"benign_mean_ms must be > 0, got {self.benign_mean_ms}")
        if self.benign_std_ms <= 0.0:
            raise ValueError(f"benign_std_ms must be > 0, got {self.benign_std_ms}")
        if self.attack_scale <= 0.0:
            raise ValueError(f"attack_scale must be > 0, got {self.attack_scale}")


# --------------------------------------------------------------- command
@dataclass(frozen=True)
class TsharkCommand:
    """The verbatim tshark command from Table 32."""

    binary: str = "tshark"
    pcap_path: str = "capture.pcap"
    display_filter: str = "dns.time > 0.1"
    fields: str = "frame.time_delta"

    def argv(self) -> list[str]:
        return [
            self.binary,
            "-r", self.pcap_path,
            "-Y", self.display_filter,
            "-T", "fields",
            "-e", self.fields,
        ]

    def __str__(self) -> str:
        return " ".join(self.argv())


def build_tshark_command(**kwargs: Any) -> TsharkCommand:
    return TsharkCommand(**kwargs)


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class S1Result:
    """Outcome of the S1 evaluation."""

    kl_divergence: float
    threshold: float
    detected: bool
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float
    tshark_available: bool
    tshark_ran: bool


# --------------------------------------------------------------- simulation
def simulate_iat(config: S1Config | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Generate benign and attack IAT samples.

    Benign samples are Gaussian. Attack samples use a log-normal so that
    the right-skew is built in, matching the "right-skewed deviation"
    description in Table 32.
    """
    cfg = config or S1Config()
    rng = np.random.default_rng(cfg.seed)
    benign = rng.normal(cfg.benign_mean_ms, cfg.benign_std_ms, size=cfg.n_samples)
    benign = np.clip(benign, 1e-3, None)
    attack = rng.lognormal(
        mean=np.log(cfg.benign_mean_ms * cfg.attack_scale),
        sigma=cfg.benign_std_ms / cfg.benign_mean_ms,
        size=cfg.n_samples,
    )
    return benign, attack


def evaluate(config: S1Config | None = None, *, use_tshark: bool = False) -> S1Result:
    """Run the S1 evaluation.

    Parameters
    ----------
    config : S1Config
        Simulation configuration.
    use_tshark : bool
        If ``True`` and ``tshark`` is installed, run the actual tshark
        command on ``capture.pcap``. In the toy and medium modes this is
        always ``False`` and the evaluation is a simulation.
    """
    cfg = config or S1Config()
    benign, attack = simulate_iat(cfg)

    # KL(P||Q) via histogram binning on the shared support.
    lo = 0.0
    hi = float(max(benign.max(), attack.max()) * 1.05)
    bins = np.linspace(lo, hi, 64)
    p, _ = np.histogram(benign, bins=bins, density=False)
    q, _ = np.histogram(attack, bins=bins, density=False)
    p = (p + 1e-12) / (p.sum() + 1e-12 * len(p))
    q = (q + 1e-12) / (q.sum() + 1e-12 * len(q))
    kl = float(np.sum(p * np.log(p / q)))

    tshark_available = shutil.which("tshark") is not None
    tshark_ran = False
    if use_tshark and tshark_available:
        cmd = build_tshark_command()
        try:
            proc = subprocess.run(cmd.argv(), capture_output=True, text=True, timeout=60)
            tshark_ran = proc.returncode == 0
        except (subprocess.SubprocessError, OSError):
            tshark_ran = False

    return S1Result(
        kl_divergence=kl,
        threshold=THRESHOLD,
        detected=kl > THRESHOLD,
        reported_success_rate=SUCCESS_RATE,
        reported_fnr=FNR,
        reported_response_ms=RESPONSE_MS,
        tshark_available=tshark_available,
        tshark_ran=tshark_ran,
    )


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for S1."""
    import json
    result = evaluate()
    print(json.dumps({
        "scenario": "S1-Timing",
        "command": str(build_tshark_command()),
        "kl_divergence": result.kl_divergence,
        "threshold": result.threshold,
        "detected": result.detected,
        "reported_success_rate": result.reported_success_rate,
        "reported_fnr": result.reported_fnr,
        "reported_response_ms": result.reported_response_ms,
        "tshark_available": result.tshark_available,
    }, indent=2))
    return 0
