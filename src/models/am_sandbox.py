"""Adaptive Multi-Protocol Sandbox (AMPS) — §6.3.2, §6.17.3.

Implements the protocol-aware isolation layer:

    * DoH  — HTTP/2 stream termination (per stream; multiplexed streams
             on the same connection are preserved).
    * DoT  — TLS 1.3 session reset (context cleared, fast re-handshake).
    * DoQ  — QUIC connection migration (session preserved; only the path
             changes).

Trigger is the KL / Rényi divergence between the current traffic
distribution and the benign baseline (§6.3.2). The sandbox's decisions
are driven by an MDP with Hamilton–Jacobi–Bellman optimal control; the
HJB solver is not part of this module (it lives in
``scripts/train_a3e.py``), but the API accepts the Q-function so the
policy can be plugged in.

Observed performance (Table 27 / §6.3.2):

    * P99 mitigation time: 1.5 ms
    * resource overhead: ≤ 15 %
    * independently benchmarked: false (§7.3 / §8.2.13)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import numpy as np

from src.protocols.base_adapter import Protocol

__all__ = [
    "AMPSConfig",
    "AMPSDecision",
    "IsolationAction",
    "AMPS",
]


# --------------------------------------------------------------- actions
class IsolationAction(str, Enum):
    """Protocol-aware isolation actions (§6.3.2)."""

    DOH_HTTP2_STREAM_TERMINATION = "doh_http2_stream_termination"
    DOT_TLS13_SESSION_RESET      = "dot_tls13_session_reset"
    DOQ_QUIC_CONNECTION_MIGRATION = "doq_quic_connection_migration"
    NO_ACTION                    = "no_action"


#: Map from protocol to its native isolation action.
_PROTOCOL_ACTION: dict[Protocol, IsolationAction] = {
    Protocol.DOH: IsolationAction.DOH_HTTP2_STREAM_TERMINATION,
    Protocol.DOT: IsolationAction.DOT_TLS13_SESSION_RESET,
    Protocol.DOQ: IsolationAction.DOQ_QUIC_CONNECTION_MIGRATION,
}


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class AMPSConfig:
    """Configuration for :class:`AMPS`.

    Attributes
    ----------
    divergence_metrics : tuple of {"kl", "renyi"}
        Divergence measures used to trigger isolation.
    renyi_alpha : float
        Order of the Rényi divergence.
    window_seconds : float
        Sliding-window length for the divergence estimate.
    threshold_floor, threshold_ceiling : float
        Adaptive threshold bounds. The actual threshold is a monotone
        function of the recent divergence history, clipped to
        ``[threshold_floor, threshold_ceiling]``.
    memory_gb, timeout_seconds, traffic_replication_factor : see Table 27.
    resource_overhead_pct : float
        Reported resource overhead (Table 27).
    p99_mitigation_ms : float
        Reported P99 mitigation time (Table 27).
    seed : int
        Master seed.
    """

    divergence_metrics: tuple[str, ...] = ("kl", "renyi")
    renyi_alpha: float = 2.0
    window_seconds: float = 10.0
    threshold_floor: float = 0.3
    threshold_ceiling: float = 3.0
    memory_gb: float = 2.0
    timeout_seconds: int = 30
    traffic_replication_factor: int = 3
    resource_overhead_pct: float = 15.0
    p99_mitigation_ms: float = 1.5
    seed: int = 20261130

    def __post_init__(self) -> None:
        for m in self.divergence_metrics:
            if m not in {"kl", "renyi"}:
                raise ValueError(f"unsupported divergence metric {m!r}")
        if self.renyi_alpha <= 1.0:
            raise ValueError(f"renyi_alpha must be > 1, got {self.renyi_alpha}")
        if self.window_seconds <= 0.0:
            raise ValueError(f"window_seconds must be > 0, got {self.window_seconds}")
        if not (0.0 <= self.threshold_floor < self.threshold_ceiling):
            raise ValueError(
                f"require 0 ≤ threshold_floor < threshold_ceiling, got "
                f"{self.threshold_floor}, {self.threshold_ceiling}"
            )
        if self.memory_gb <= 0.0:
            raise ValueError(f"memory_gb must be > 0, got {self.memory_gb}")
        if self.timeout_seconds <= 0:
            raise ValueError(f"timeout_seconds must be > 0, got {self.timeout_seconds}")
        if self.traffic_replication_factor < 1:
            raise ValueError(
                f"traffic_replication_factor must be ≥ 1, got {self.traffic_replication_factor}"
            )
        if self.resource_overhead_pct < 0.0 or self.resource_overhead_pct > 100.0:
            raise ValueError(
                f"resource_overhead_pct must be in [0, 100], got {self.resource_overhead_pct}"
            )
        if self.p99_mitigation_ms <= 0.0:
            raise ValueError(f"p99_mitigation_ms must be > 0, got {self.p99_mitigation_ms}")


# --------------------------------------------------------------- decision
@dataclass(frozen=True)
class AMPSDecision:
    """A single isolation decision."""

    flow_key: str
    protocol: Protocol
    divergence_kl: float
    divergence_renyi: float
    threshold: float
    action: IsolationAction
    mitigated: bool


# --------------------------------------------------------------- sandbox
class AMPS:
    """Adaptive Multi-Protocol Sandbox.

    Parameters
    ----------
    config : AMPSConfig
        Sandbox configuration.

    Notes
    -----
    * The MDP / HJB optimal control is not implemented in this class;
      the sandbox exposes the divergence estimate and the adaptive
      threshold, and the caller (the training loop) supplies the Q
      function through :meth:`decide`.
    * All isolation actions are **logical** in this module: they return
      the action tag and ``mitigated=True/False``, and the actual
      packet-level enforcement is performed by the protocol adapter in
      the real pipeline. This keeps the sandbox testable without a live
      network.
    """

    def __init__(self, config: AMPSConfig | None = None) -> None:
        self.config = config or AMPSConfig()
        self._rng = np.random.default_rng(self.config.seed)
        self._history: list[float] = []

    # --------------------------------------------------------------- threshold
    def adaptive_threshold(self) -> float:
        """Return the current adaptive threshold in
        ``[threshold_floor, threshold_ceiling]``.

        The threshold is ``floor + (ceiling − floor) · sigmoid(recent_mean)``
        clipped to the configured range, so that a history of high
        divergences raises the threshold gradually (avoids flapping).
        """
        if not self._history:
            return self.config.threshold_floor
        recent = np.asarray(self._history[-32:], dtype=np.float64)
        s = 1.0 / (1.0 + np.exp(-float(np.mean(recent))))
        lo, hi = self.config.threshold_floor, self.config.threshold_ceiling
        return float(lo + (hi - lo) * s)

    # --------------------------------------------------------------- divergence
    def _kl(self, p: np.ndarray, q: np.ndarray) -> float:
        p = np.asarray(p, dtype=np.float64)
        q = np.asarray(q, dtype=np.float64)
        p = p / max(p.sum(), 1e-12)
        q = q / max(q.sum(), 1e-12)
        mask = p > 0
        return float(np.sum(p[mask] * np.log(p[mask] / q[mask])))

    def _renyi(self, p: np.ndarray, q: np.ndarray) -> float:
        alpha = self.config.renyi_alpha
        p = np.asarray(p, dtype=np.float64)
        q = np.asarray(q, dtype=np.float64)
        p = p / max(p.sum(), 1e-12)
        q = q / max(q.sum(), 1e-12)
        mask = p > 0
        integrand = np.sum((p[mask] ** alpha) * (q[mask] ** (1.0 - alpha)))
        return float(np.log(max(integrand, 1e-300)) / (alpha - 1.0))

    # --------------------------------------------------------------- decide
    def decide(
        self,
        *,
        flow_key: str,
        protocol: Protocol,
        observed: np.ndarray,
        baseline: np.ndarray,
    ) -> AMPSDecision:
        """Estimate the divergence and return an isolation decision."""
        kl = self._kl(observed, baseline)
        renyi = self._renyi(observed, baseline) if "renyi" in self.config.divergence_metrics else 0.0

        # Combine: use the max of the requested metrics; this keeps the
        # trigger conservative (isolate when either signal is high).
        signal = max(kl, renyi if "renyi" in self.config.divergence_metrics else kl)
        self._history.append(signal)
        threshold = self.adaptive_threshold()

        if signal > threshold:
            action = _PROTOCOL_ACTION[protocol]
            mitigated = True
        else:
            action = IsolationAction.NO_ACTION
            mitigated = False

        return AMPSDecision(
            flow_key=flow_key,
            protocol=protocol,
            divergence_kl=kl,
            divergence_renyi=renyi,
            threshold=threshold,
            action=action,
            mitigated=mitigated,
        )

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "divergence_metrics": list(self.config.divergence_metrics),
            "renyi_alpha": self.config.renyi_alpha,
            "window_seconds": self.config.window_seconds,
            "threshold_floor": self.config.threshold_floor,
            "threshold_ceiling": self.config.threshold_ceiling,
            "memory_gb": self.config.memory_gb,
            "timeout_seconds": self.config.timeout_seconds,
            "traffic_replication_factor": self.config.traffic_replication_factor,
            "resource_overhead_pct": self.config.resource_overhead_pct,
            "p99_mitigation_ms": self.config.p99_mitigation_ms,
            "independently_benchmarked": False,
        }
