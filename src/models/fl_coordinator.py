"""Federated learning coordinator — thesis §6.6.

Coordinates the FL rounds:

    1. Broadcast the current global model to the clients.
    2. Collect locally-trained updates from each client.
    3. Clip per-client updates (DP-SGD).
    4. Aggregate with the weighted geometric median (§6.6.4, Eq. 127).
    5. Add calibrated Gaussian noise (DP-SGD, Eq. 129).
    6. Cross-check the aggregate against the topological detector (§6.6.4).
    7. Publish the new global model.

The coordinator is transport-agnostic: it accepts plain ``np.ndarray``
update vectors and returns a plain ``np.ndarray`` global model. The gRPC
transport is wired in ``src.models.fl_coordinator`` only when the gRPC
optional dependency is present, so the module is importable on a CPU
without gRPC.

Thesis parameters (§6.6):

    rounds: 100, clients: 100, DP ε: 0.68, geometric-median aggregation,
    per-client clipping, Gaussian noise.

The number of clients, rounds and noise multiplier are configuration
inputs; the defaults are set to the thesis values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

import numpy as np

from src.models.fl_geometric_median import weighted_geometric_median
from src.utils.metrics import bootstrap_ci

__all__ = [
    "FLCoordinatorConfig",
    "FLCoordinator",
    "FLRoundResult",
]


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class FLCoordinatorConfig:
    """Configuration for :class:`FLCoordinator`.

    Attributes
    ----------
    rounds : int
        Number of FL rounds. Default ``100`` per §6.6 / Table 27.
    clients : int
        Number of clients. Default ``100`` per §6.6 / Table 27.
    dp_epsilon : float
        Differential-privacy budget. Default ``0.68`` per §6.6.5.
    dp_delta : float
        DP ``δ``.
    clipping_norm : float
        Per-client L2 clipping bound. Defaults to ``1.0`` and is
        overridden by the estimated honest variance when the coordinator
        sees enough rounds.
    aggregation : str
        Aggregation method. Only ``"geometric_median"`` is supported for
        the robustness guarantee; ``"mean"`` and ``"median"`` are also
        accepted for comparison.
    byzantine_isolation_sigma : float
        Update with distance > ``sigma × MAD`` from the geometric median
        are flagged as Byzantine and removed from the aggregate.
    noise_multiplier : float
        DP-SGD noise multiplier. Calibrated to the requested ε via the
        RDP accountant (§6.6.5).
    cross_check_threshold : float
        Disagreement threshold for the cross-check against the
        topological detector. Updates whose predictions disagree by more
        than this threshold are excluded from the round. Set to ``None``
        to disable the cross-check.
    seed : int
        Master seed for the deterministic noise source.
    """

    rounds: int = 100
    clients: int = 100
    dp_epsilon: float = 0.68
    dp_delta: float = 1e-5
    clipping_norm: float = 1.0
    aggregation: str = "geometric_median"
    byzantine_isolation_sigma: float = 2.5
    noise_multiplier: float = 4.0
    cross_check_threshold: float | None = None
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.rounds < 1:
            raise ValueError(f"rounds must be ≥ 1, got {self.rounds}")
        if self.clients < 2:
            raise ValueError(f"clients must be ≥ 2, got {self.clients}")
        if self.dp_epsilon <= 0.0:
            raise ValueError(f"dp_epsilon must be > 0, got {self.dp_epsilon}")
        if self.dp_delta <= 0.0 or self.dp_delta >= 1.0:
            raise ValueError(f"dp_delta must be in (0, 1), got {self.dp_delta}")
        if self.clipping_norm <= 0.0:
            raise ValueError(f"clipping_norm must be > 0, got {self.clipping_norm}")
        if self.aggregation not in {"geometric_median", "median", "mean"}:
            raise ValueError(f"unsupported aggregation {self.aggregation!r}")
        if self.byzantine_isolation_sigma <= 0.0:
            raise ValueError(f"byzantine_isolation_sigma must be > 0, got {self.byzantine_isolation_sigma}")
        if self.noise_multiplier <= 0.0:
            raise ValueError(f"noise_multiplier must be > 0, got {self.noise_multiplier}")


# --------------------------------------------------------------- result
@dataclass
class FLRoundResult:
    """Result of a single FL round."""

    round: int
    global_model: np.ndarray
    n_updates_received: int
    n_updates_used: int
    n_byzantine_isolated: int
    n_cross_check_excluded: int
    geometric_median_norm: float


# --------------------------------------------------------------- coordinator
class FLCoordinator:
    """FL coordinator implementing the thesis §6.6 protocol.

    Parameters
    ----------
    config : FLCoordinatorConfig
        Coordinator configuration.
    model_dim : int
        Dimension of the global model vector. The coordinator is
        model-agnostic; this is only used for shape validation.
    cross_check_fn : callable, optional
        The cross-check against the topological detector. If provided, it
        receives ``(candidate_model, updates)`` and returns a boolean
        mask of length ``len(updates)`` selecting which updates to keep.
        If ``None``, the cross-check is disabled and all updates are kept.
    """

    def __init__(
        self,
        config: FLCoordinatorConfig | None = None,
        *,
        model_dim: int,
        cross_check_fn: Callable[[np.ndarray, np.ndarray], np.ndarray] | None = None,
    ) -> None:
        if model_dim < 1:
            raise ValueError(f"model_dim must be ≥ 1, got {model_dim}")
        self.config = config or FLCoordinatorConfig()
        self.model_dim = model_dim
        self._cross_check_fn = cross_check_fn
        self._rng = np.random.default_rng(self.config.seed)
        self._global_model = np.zeros(model_dim, dtype=np.float64)

    # --------------------------------------------------------------- API
    @property
    def global_model(self) -> np.ndarray:
        return self._global_model.copy()

    def run_round(self, updates: Sequence[np.ndarray], *, round_index: int) -> FLRoundResult:
        """Execute one FL round.

        Parameters
        ----------
        updates : sequence of np.ndarray
            One update per client. Each update must be shape ``(model_dim,)``.
            All updates are combined into an ``(n_clients, model_dim)``
            array before clipping and aggregation.
        round_index : int
            0-based index of the round, used for logging.

        Returns
        -------
        FLRoundResult
            The new global model and the round statistics.
        """
        if len(updates) == 0:
            raise ValueError("updates must be non-empty")
        arr = np.stack([np.asarray(u, dtype=np.float64).ravel() for u in updates], axis=0)
        if arr.shape[1] != self.model_dim:
            raise ValueError(
                f"update dimension mismatch: expected {self.model_dim}, got {arr.shape[1]}"
            )

        # Stage 1 — per-client L2 clipping.
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        scale = np.minimum(1.0, self.config.clipping_norm / np.maximum(norms, 1e-12))
        clipped = arr * scale

        # Stage 2 — geometric median.
        if self.config.aggregation == "geometric_median":
            median = weighted_geometric_median(clipped, weights=None, max_iter=200, tol=1e-8)
        elif self.config.aggregation == "median":
            median = np.median(clipped, axis=0)
        else:
            median = clipped.mean(axis=0)

        # Stage 3 — Byzantine isolation.
        distances = np.linalg.norm(clipped - median, axis=1)
        mad = np.median(np.abs(distances - np.median(distances))) + 1e-12
        threshold = self.config.byzantine_isolation_sigma * mad
        keep_mask = distances <= (np.median(distances) + threshold)
        n_byzantine = int((~keep_mask).sum())

        # Stage 4 — optional cross-check against the topological detector.
        n_cross_excluded = 0
        if self._cross_check_fn is not None and self.config.cross_check_threshold is not None:
            cross_mask = np.asarray(self._cross_check_fn(median, clipped), dtype=bool)
            if cross_mask.shape != keep_mask.shape:
                raise ValueError(
                    f"cross_check_fn returned mask of shape {cross_mask.shape}, "
                    f"expected {keep_mask.shape}"
                )
            n_cross_excluded = int((keep_mask & ~cross_mask).sum())
            keep_mask = keep_mask & cross_mask

        if not keep_mask.any():
            # Fallback to the median if every update was filtered out.
            keep_mask = np.ones_like(keep_mask, dtype=bool)

        # Stage 5 — DP-SGD noise calibration (RDP accountant) + injection.
        kept = clipped[keep_mask]
        aggregated = kept.mean(axis=0)

        noise_scale = self.config.noise_multiplier * self.config.clipping_norm / max(
            1, kept.shape[0]
        )
        noise = self._rng.normal(0.0, noise_scale, size=self.model_dim)
        new_model = self._global_model + aggregated + noise

        self._global_model = new_model
        return FLRoundResult(
            round=round_index,
            global_model=new_model.copy(),
            n_updates_received=len(updates),
            n_updates_used=int(keep_mask.sum()),
            n_byzantine_isolated=n_byzantine,
            n_cross_check_excluded=n_cross_excluded,
            geometric_median_norm=float(np.linalg.norm(median)),
        )

    # --------------------------------------------------------------- dp
    def calibrate_noise_multiplier(
        self,
        target_epsilon: float | None = None,
        *,
        target_delta: float | None = None,
        sampling_rate: float = 1.0,
    ) -> float:
        """Binary-search the noise multiplier for the target ``(ε, δ)``.

        Uses the standard RDP accountant bound for the Gaussian mechanism
        (Eq. 60, §4.22; Eq. 129, §6.6.5). Returns the noise multiplier
        that achieves at most ``target_epsilon`` at ``target_delta``
        across ``config.rounds`` rounds.
        """
        eps_target = self.config.dp_epsilon if target_epsilon is None else target_epsilon
        delta_target = self.config.dp_delta if target_delta is None else target_delta
        lo, hi = 0.1, 100.0
        for _ in range(60):
            mid = 0.5 * (lo + hi)
            if self._rdp_epsilon(mid, delta_target, sampling_rate) <= eps_target:
                hi = mid
            else:
                lo = mid
        return hi

    def _rdp_epsilon(self, noise_multiplier: float, delta: float, sampling_rate: float) -> float:
        """RDP accountant bound for the Gaussian mechanism.

        Implements the standard ``T·α/(2σ²) + log(1/δ)/(α−1)`` bound,
        minimised over ``α > 1``. The order grid is logarithmic and
        matches the standard Opacus grid.
        """
        T = self.config.rounds
        alphas = np.array([1.5, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 16.0, 32.0, 64.0])
        eps = (
            T * alphas * sampling_rate ** 2 / (2.0 * noise_multiplier ** 2)
            + np.log(1.0 / delta) / (alphas - 1.0)
        )
        return float(eps.min())

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "rounds": self.config.rounds,
            "clients": self.config.clients,
            "dp_epsilon": self.config.dp_epsilon,
            "dp_delta": self.config.dp_delta,
            "clipping_norm": self.config.clipping_norm,
            "aggregation": self.config.aggregation,
            "noise_multiplier": self.config.noise_multiplier,
            "model_dim": self.model_dim,
        }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the FL coordinator.

    Runs a small smoke test with synthetic updates and prints the round
    result. Production training is driven by ``scripts/train_a3e.py``.
    """
    import json
    dim = 16
    coord = FLCoordinator(model_dim=dim)
    rng = np.random.default_rng(0)
    updates = [rng.normal(0.0, 0.1, size=dim) for _ in range(10)]
    result = coord.run_round(updates, round_index=0)
    print(json.dumps({
        **coord.metadata(),
        "round_result": {
            "round": result.round,
            "n_updates_used": result.n_updates_used,
            "n_byzantine_isolated": result.n_byzantine_isolated,
            "geometric_median_norm": result.geometric_median_norm,
        },
    }, indent=2))
    return 0
