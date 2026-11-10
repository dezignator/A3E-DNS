"""S5 — Adversarial evasion scenario. Thesis Table 32.

The S5 scenario is an **ML-evasion** attack in which adversarial DNS
queries are crafted to evade learned classifiers. The tool used in the
thesis is IBM's Adversarial Robustness Toolbox (ART); the exact command
is reproduced from Table 32.

Command (Table 32)
------------------

    python craft_queries.py -model blackbox -epsilon 0.15

Traffic pattern
---------------

    GAN-crafted adversarial DNS queries designed to evade learned
    classifiers.

Detection threshold
-------------------

    Detection confidence drop exceeds 20 %.

Reported performance (Table 32)
-------------------------------

    Success : 97.8 %
    FNR     : 2.2 %
    Response: 0.9 ms

The module produces a deterministic simulation of the evasion attack
(``simulate_adversarial_queries``) and evaluates the confidence-drop
test (``evaluate``).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "S5Config",
    "S5Result",
    "simulate_adversarial_queries",
    "evaluate",
    "build_command",
    "run",
    "SUCCESS_RATE",
    "FNR",
    "RESPONSE_MS",
    "EPSILON",
    "CONFIDENCE_DROP_PCT",
]


#: Table 32 values for S5.
SUCCESS_RATE: float = 97.8
FNR: float = 2.2
RESPONSE_MS: float = 0.9
EPSILON: float = 0.15
CONFIDENCE_DROP_PCT: float = 20.0


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class S5Config:
    """Configuration for the S5 simulation.

    Attributes
    ----------
    n_queries : int
        Number of adversarial queries to generate.
    epsilon : float
        L∞ perturbation bound (0.15 in the thesis).
    clean_confidence : float
        Classifier confidence on clean inputs.
    adversarial_drop : float
        Fractional confidence drop under adversarial perturbation.
    seed : int
        Master seed for reproducibility.
    """

    n_queries: int = 1000
    epsilon: float = EPSILON
    clean_confidence: float = 0.95
    adversarial_drop: float = 0.25
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.n_queries < 10:
            raise ValueError(f"n_queries must be ≥ 10, got {self.n_queries}")
        if not (0.0 < self.epsilon < 1.0):
            raise ValueError(f"epsilon must be in (0, 1), got {self.epsilon}")
        if not (0.0 < self.clean_confidence < 1.0):
            raise ValueError(
                f"clean_confidence must be in (0, 1), got {self.clean_confidence}"
            )
        if not (0.0 < self.adversarial_drop < 1.0):
            raise ValueError(
                f"adversarial_drop must be in (0, 1), got {self.adversarial_drop}"
            )


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class S5Result:
    """Outcome of the S5 evaluation."""

    mean_clean_confidence: float
    mean_adversarial_confidence: float
    mean_confidence_drop_pct: float
    threshold_pct: float
    detected: bool
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float
    art_available: bool


# --------------------------------------------------------------- command
def build_command() -> str:
    """The verbatim S5 command from Table 32."""
    return f"python craft_queries.py -model blackbox -epsilon {EPSILON}"


# --------------------------------------------------------------- simulation
def simulate_adversarial_queries(
    config: S5Config | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate paired clean and adversarial classifier confidences.

    Returns
    -------
    (clean, adversarial) : tuple of np.ndarray
        Per-query confidence on the clean and adversarial inputs.
    """
    cfg = config or S5Config()
    rng = np.random.default_rng(cfg.seed)
    clean = np.clip(
        rng.normal(cfg.clean_confidence, 0.02, size=cfg.n_queries), 0.0, 1.0
    )
    adversarial = np.clip(
        clean * (1.0 - cfg.adversarial_drop) + rng.normal(0.0, 0.01, size=cfg.n_queries),
        0.0,
        1.0,
    )
    return clean, adversarial


def evaluate(config: S5Config | None = None) -> S5Result:
    """Run the S5 evaluation."""
    cfg = config or S5Config()
    clean, adversarial = simulate_adversarial_queries(cfg)

    mean_clean = float(clean.mean())
    mean_adv = float(adversarial.mean())
    drop_pct = float(100.0 * (mean_clean - mean_adv) / max(mean_clean, 1e-12))
    art_available = shutil.which("art") is not None or _has_art_module()

    return S5Result(
        mean_clean_confidence=mean_clean,
        mean_adversarial_confidence=mean_adv,
        mean_confidence_drop_pct=drop_pct,
        threshold_pct=CONFIDENCE_DROP_PCT,
        detected=drop_pct > CONFIDENCE_DROP_PCT,
        reported_success_rate=SUCCESS_RATE,
        reported_fnr=FNR,
        reported_response_ms=RESPONSE_MS,
        art_available=art_available,
    )


def _has_art_module() -> bool:
    try:
        import art  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for S5."""
    import json
    result = evaluate()
    print(json.dumps({
        "scenario": "S5-Evasion",
        "command": build_command(),
        "mean_clean_confidence": result.mean_clean_confidence,
        "mean_adversarial_confidence": result.mean_adversarial_confidence,
        "mean_confidence_drop_pct": result.mean_confidence_drop_pct,
        "threshold_pct": result.threshold_pct,
        "detected": result.detected,
        "reported_success_rate": result.reported_success_rate,
        "reported_fnr": result.reported_fnr,
        "reported_response_ms": result.reported_response_ms,
        "art_available": result.art_available,
    }, indent=2))
    return 0
