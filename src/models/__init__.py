"""Model subpackage for the A3E-DNS thesis artifact (Chapter 6).

Public modules:

    aee_engine          — Adaptive Evolutionary Encryption (§6.4, Eqs. 119–122)
    aee_neural_controller — 2×64 MLP controller (§6.4.5)
    qhe_engine          — Optimized Quantum-Safe Homomorphic Encryption (§6.5)
    qhe_ntt             — Number Theoretic Transform (§6.5.1)
    qhe_ziggurat        — Precomputed Gaussian sampler (§6.5.2)
    fl_coordinator      — Federated learning coordinator (§6.6)
    fl_transformer      — 8-layer, 12-head spatio-temporal transformer (§6.6.1)
    fl_geometric_median — Byzantine-robust aggregation (§6.6.4, Eq. 127)
    fl_dp_sgd           — DP-SGD with (ε = 0.68) (§6.6.5)
    am_sandbox          — Adaptive Multi-Protocol Sandbox (§6.3.2, §6.17.3)
    anomaly_detector    — Transformer-based detector (§6.6.1, Table 27)
"""

from __future__ import annotations

__all__ = [
    "aee_engine",
    "aee_neural_controller",
    "qhe_engine",
    "qhe_ntt",
    "qhe_ziggurat",
    "fl_coordinator",
    "fl_transformer",
    "fl_geometric_median",
    "fl_dp_sgd",
    "am_sandbox",
    "anomaly_detector",
]
