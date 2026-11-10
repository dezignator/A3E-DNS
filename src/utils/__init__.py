"""Utility subpackage for the A3E-DNS thesis artifact (Chapter 6).

Public modules:

    math_utils                — so(3) / se(3) primitives
    se3_lie_group             — SE(3)ⁿ exp/log/projection
    seed                      — deterministic seeding
    logger                    — structured JSON logging
    metrics                   — accuracy, FPR, P99, AUPRC, F1, Cohen's d, JSD
    config_loader             — YAML + JSON schema validation
    composite_detection_score — Composite Detection Score (Eq. 131)

Heavy dependencies are deferred to keep `import src.utils` cheap.
"""

from __future__ import annotations

__all__ = [
    "math_utils",
    "se3_lie_group",
    "seed",
    "logger",
    "metrics",
    "config_loader",
    "composite_detection_score",
]
