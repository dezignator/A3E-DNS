"""Hardware emulation for the A3E-DNS artifact (Chapter 6).

The thesis relies on three pieces of specialised hardware that are not
universally available to reviewers:

    * NVIDIA A100 GPU  (40 GB HBM, 6,912 CUDA cores, ~2.5 TOPS)
    * Intel Loihi 2    (neuromorphic; 128 cores × 1,024 LIF neurons)
    * P4 / BMv2        (programmable switch, software-model)

This subpackage provides **deterministic emulators** that reproduce the
reported *trends* so that the artifact is runnable on a stock CPU. The
absolute numbers reported in the thesis are properties of the real
hardware; the emulators preserve ordering, ratios, and qualitative
behaviour, but do not claim to reproduce the exact figures on real
hardware. This is stated in §7.3.4 of the thesis and in
``REPRODUCIBILITY_CHECKLIST.md`` (Tier B / C).

Modules
-------

    a100_emulation   — A100 performance model for QHE operations
    loihi_mock       — Loihi 2 energy and latency model for SNN
    entropy          — Hardware entropy sources (RDRAND / RDSEED / urandom)
    perf_model       — Top-level performance model stitching the three

The emulation pathway is **the intended reproduction path** for
independent reviewers (Tier B). See ``docs/HARDWARE_EMULATION.md``.
"""

from __future__ import annotations

__all__ = [
    "a100_emulation",
    "loihi_mock",
    "entropy",
    "perf_model",
]
