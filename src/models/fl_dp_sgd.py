"""DP-SGD with RDP accountant — §6.6.5, Eqs. 129–130.

Implements the standard DP-SGD update of Abadi et al. (CCS 2016):

    W_{t+1} = W_t − η · ( (1/K) Σ_k Clip_C(∇F_k) + N(0, σ² C² I) )

and the RDP accountant bound (§4.22, Eq. 60; §6.6.5, Eq. 129):

    ε(δ) = min_{α > 1} [ T·α/(2σ²) + log(1/δ)/(α−1) ]

The thesis reports the operating point ``ε = 0.68`` (§6.6.5). The
default ``DPConfig`` matches that value; the accountant is used to
calibrate the noise multiplier that achieves it for the configured
number of rounds.

This module is the coordinator-side DP primitive. The client-side
gradient computation is not implemented here; the coordinator receives
already-computed per-client updates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "DPConfig",
    "DPSGDMechanism",
    "clip_update",
    "inject_gaussian_noise",
]


@dataclass(frozen=True)
class DPConfig:
    """Configuration for :class:`DPSGDMechanism`.

    Attributes
    ----------
    epsilon : float
        Target DP budget. Default ``0.68`` per §6.6.5.
    delta : float
        DP ``δ``.
    clipping_norm : float
        Per-client clipping bound ``C``.
    noise_multiplier : float
        DP-SGD noise multiplier ``σ``. Calibrated by :meth:`calibrate`.
    rounds : int
        Number of FL rounds for the accountant.
    sampling_rate : float
        Poisson sampling rate. Defaults to ``1.0``.
    seed : int
        Master seed for the noise RNG.
    """

    epsilon: float = 0.68
    delta: float = 1e-5
    clipping_norm: float = 1.0
    noise_multiplier: float = 4.0
    rounds: int = 100
    sampling_rate: float = 1.0
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.epsilon <= 0.0:
            raise ValueError(f"epsilon must be > 0, got {self.epsilon}")
        if not (0.0 < self.delta < 1.0):
            raise ValueError(f"delta must be in (0, 1), got {self.delta}")
        if self.clipping_norm <= 0.0:
            raise ValueError(f"clipping_norm must be > 0, got {self.clipping_norm}")
        if self.noise_multiplier <= 0.0:
            raise ValueError(f"noise_multiplier must be > 0, got {self.noise_multiplier}")
        if self.rounds < 1:
            raise ValueError(f"rounds must be ≥ 1, got {self.rounds}")
        if not (0.0 < self.sampling_rate <= 1.0):
            raise ValueError(f"sampling_rate must be in (0, 1], got {self.sampling_rate}")


def clip_update(grad: np.ndarray, C: float) -> np.ndarray:
    """L2-clip a single client's update."""
    if C <= 0.0:
        raise ValueError(f"C must be > 0, got {C}")
    grad = np.asarray(grad, dtype=np.float64)
    norm = float(np.linalg.norm(grad))
    if norm <= C:
        return grad
    return grad * (C / norm)


def inject_gaussian_noise(
    aggregate: np.ndarray,
    *,
    noise_multiplier: float,
    clipping_norm: float,
    n_clients: int,
    rng: np.random.Generator,
) -> np.ndarray:
    """Add DP-SGD Gaussian noise to the aggregate update.

    The noise scale is ``σ · C / K`` where ``K`` is the number of
    clients. This matches Eq. 36 of §4.6.2 and the DP-SGD formulation
    in Eq. 129.
    """
    aggregate = np.asarray(aggregate, dtype=np.float64)
    if n_clients < 1:
        raise ValueError(f"n_clients must be ≥ 1, got {n_clients}")
    scale = noise_multiplier * clipping_norm / n_clients
    return aggregate + rng.normal(0.0, scale, size=aggregate.shape)


class DPSGDMechanism:
    """DP-SGD wrapper with a public calibration API.

    Parameters
    ----------
    config : DPConfig
        DP configuration.
    """

    def __init__(self, config: DPConfig | None = None) -> None:
        self.config = config or DPConfig()
        self._rng = np.random.default_rng(self.config.seed)

    # --------------------------------------------------------------- step
    def aggregate(self, updates: np.ndarray) -> np.ndarray:
        """Clip, average, and add DP noise to a batch of client updates.

        Parameters
        ----------
        updates : np.ndarray, shape ``(K, d)``
            One update per client.

        Returns
        -------
        np.ndarray, shape ``(d,)``
            The noisy aggregate.
        """
        updates = np.asarray(updates, dtype=np.float64)
        if updates.ndim != 2:
            raise ValueError(f"updates must be 2-D, got shape {updates.shape}")
        K = updates.shape[0]
        if K < 1:
            raise ValueError("updates must have at least one row")

        clipped = np.stack([clip_update(u, self.config.clipping_norm) for u in updates], axis=0)
        mean = clipped.mean(axis=0)
        return inject_gaussian_noise(
            mean,
            noise_multiplier=self.config.noise_multiplier,
            clipping_norm=self.config.clipping_norm,
            n_clients=K,
            rng=self._rng,
        )

    # --------------------------------------------------------------- accountant
    def epsilon_at(self, noise_multiplier: float) -> float:
        """Return the RDP-accountant bound ``ε`` for ``noise_multiplier``."""
        T = self.config.rounds
        q = self.config.sampling_rate
        alphas = np.array([1.5, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 16.0, 32.0, 64.0])
        eps = (
            T * alphas * q ** 2 / (2.0 * noise_multiplier ** 2)
            + np.log(1.0 / self.config.delta) / (alphas - 1.0)
        )
        return float(eps.min())

    def calibrate(self, target_epsilon: float | None = None) -> float:
        """Return the noise multiplier that achieves the target ``ε``."""
        target = self.config.epsilon if target_epsilon is None else target_epsilon
        lo, hi = 0.1, 100.0
        for _ in range(60):
            mid = 0.5 * (lo + hi)
            if self.epsilon_at(mid) <= target:
                hi = mid
            else:
                lo = mid
        return hi

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "epsilon": self.config.epsilon,
            "delta": self.config.delta,
            "clipping_norm": self.config.clipping_norm,
            "noise_multiplier": self.config.noise_multiplier,
            "rounds": self.config.rounds,
            "sampling_rate": self.config.sampling_rate,
            "epsilon_at_config": self.epsilon_at(self.config.noise_multiplier),
        }
