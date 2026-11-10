"""S3 — Model poisoning scenario. Thesis Table 32.

The S3 scenario is a **federated-learning model-poisoning** attack in
which a fraction of the clients submit biased updates. The tool used in
the thesis is ``fl-attack`` (a wrapper around ``poison.py``); the exact
command is reproduced from Table 32.

Command (Table 32)
------------------

    python poison.py --malicious-updates 7 --bias 0.25

Traffic pattern
---------------

    Federated learning updates follow biased distribution
    δ ~ N(0.25, 0.1).

Detection threshold
-------------------

    Model weight deviation exceeds 2σ.

Reported performance (Table 32)
-------------------------------

    Success : 96.5 %
    FNR     : 3.5 %
    Response: 2.5 ms

This module produces a deterministic simulation of the poisoning attack
(``simulate_updates``) and evaluates the MAD-based detection
(``evaluate``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from src.models.fl_geometric_median import weighted_geometric_median, mad_threshold

__all__ = [
    "S3Config",
    "S3Result",
    "simulate_updates",
    "evaluate",
    "build_command",
    "run",
    "SUCCESS_RATE",
    "FNR",
    "RESPONSE_MS",
    "BIAS_MEAN",
    "BIAS_STD",
    "THRESHOLD_SIGMA",
    "MALICIOUS_UPDATES",
]


#: Table 32 values for S3.
SUCCESS_RATE: float = 96.5
FNR: float = 3.5
RESPONSE_MS: float = 2.5
BIAS_MEAN: float = 0.25
BIAS_STD: float = 0.1
THRESHOLD_SIGMA: float = 2.0
MALICIOUS_UPDATES: int = 7


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class S3Config:
    """Configuration for the S3 simulation.

    Attributes
    ----------
    n_clients : int
        Total number of federated clients.
    n_malicious : int
        Number of malicious clients (7 in the thesis).
    model_dim : int
        Dimensionality of the model update vector.
    bias_mean, bias_std : float
        Mean and std of the malicious bias.
    honest_std : float
        Standard deviation of honest updates.
    seed : int
        Master seed for reproducibility.
    """

    n_clients: int = 20
    n_malicious: int = MALICIOUS_UPDATES
    model_dim: int = 16
    bias_mean: float = BIAS_MEAN
    bias_std: float = BIAS_STD
    honest_std: float = 0.05
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n_clients < 2:
            raise ValueError(f"n_clients must be ≥ 2, got {self.n_clients}")
        if not (0 <= self.n_malicious < self.n_clients):
            raise ValueError(
                f"n_malicious must be in [0, n_clients), got {self.n_malicious}"
            )
        if self.model_dim < 1:
            raise ValueError(f"model_dim must be ≥ 1, got {self.model_dim}")
        if self.bias_std <= 0.0:
            raise ValueError(f"bias_std must be > 0, got {self.bias_std}")
        if self.honest_std <= 0.0:
            raise ValueError(f"honest_std must be > 0, got {self.honest_std}")


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class S3Result:
    """Outcome of the S3 evaluation."""

    detected: bool
    n_malicious_detected: int
    n_malicious_total: int
    deviation_norm: float
    threshold_norm: float
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float


# --------------------------------------------------------------- command
def build_command() -> str:
    """The verbatim S3 command from Table 32."""
    return f"python poison.py --malicious-updates {MALICIOUS_UPDATES} --bias {BIAS_MEAN}"


# --------------------------------------------------------------- simulation
def simulate_updates(config: S3Config | None = None) -> np.ndarray:
    """Generate client updates, some of them malicious.

    Returns
    -------
    np.ndarray, shape ``(n_clients, model_dim)``
        The client updates. The first ``n_malicious`` rows are malicious.
    """
    cfg = config or S3Config()
    rng = np.random.default_rng(cfg.seed)
    honest = rng.normal(0.0, cfg.honest_std, size=(cfg.n_clients - cfg.n_malicious, cfg.model_dim))
    biased = cfg.bias_mean + rng.normal(0.0, cfg.bias_std, size=(cfg.n_malicious, cfg.model_dim))
    return np.vstack([biased, honest])


def evaluate(config: S3Config | None = None) -> S3Result:
    """Run the S3 evaluation."""
    cfg = config or S3Config()
    updates = simulate_updates(cfg)
    n_total, dim = updates.shape

    median = weighted_geometric_median(updates, max_iter=500, tol=1e-8)
    deviations = np.linalg.norm(updates - median, axis=1)
    threshold = mad_threshold(deviations, sigma=THRESHOLD_SIGMA)
    flagged = deviations > threshold

    # The malicious clients are the first n_malicious rows by construction.
    is_malicious = np.zeros(n_total, dtype=bool)
    is_malicious[: cfg.n_malicious] = True
    n_mal_detected = int((flagged & is_malicious).sum())

    return S3Result(
        detected=bool(n_mal_detected > 0),
        n_malicious_detected=n_mal_detected,
        n_malicious_total=cfg.n_malicious,
        deviation_norm=float(np.linalg.norm(deviations)),
        threshold_norm=float(threshold),
        reported_success_rate=SUCCESS_RATE,
        reported_fnr=FNR,
        reported_response_ms=RESPONSE_MS,
    )


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for S3."""
    import json
    result = evaluate()
    print(json.dumps({
        "scenario": "S3-Poison",
        "command": build_command(),
        "detected": result.detected,
        "n_malicious_detected": result.n_malicious_detected,
        "n_malicious_total": result.n_malicious_total,
        "deviation_norm": result.deviation_norm,
        "threshold_norm": result.threshold_norm,
        "reported_success_rate": result.reported_success_rate,
        "reported_fnr": result.reported_fnr,
        "reported_response_ms": result.reported_response_ms,
    }, indent=2))
    return 0
