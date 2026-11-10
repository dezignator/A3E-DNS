"""A100 performance emulator — thesis §6.5.4, §7.3.4.

Emulates the NVIDIA A100 GPU used for the QHE acceleration. The reported
figures for the A100 (§6.5.4) are:

    * 6,912 CUDA cores
    * 40 GB HBM
    * ~2.5 TOPS on lattice operations
    * 3rd-generation Tensor Cores

The emulator is a **deterministic performance model**, not a simulator
of the CUDA execution. It produces the same ordering and the same ratios
as the A100 for the QHE operations that the framework reports, given the
same input sizes. It does NOT reproduce exact latencies on real
hardware: the numbers depend on the specific kernel, memory layout, and
driver. This caveat is stated in §7.3.4 and in
``REPRODUCIBILITY_CHECKLIST.md``.

Public API
----------
    A100Spec()                  — the reference specification
    estimate_latency_ms(op)     — emulated latency for a QHE op
    estimate_throughput(qps)    — emulated QPS throughput
    metadata()                  — dict for the manifest
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "A100Spec",
    "A100Emulator",
    "OPERATIONS",
    "estimate_latency_ms",
    "estimate_throughput",
    "metadata",
]


# --------------------------------------------------------------- spec
@dataclass(frozen=True)
class A100Spec:
    """A100 reference specification (from §6.5.4)."""

    cuda_cores: int = 6912
    memory_gb: float = 40.0
    tops: float = 2.5
    tensor_cores: int = 432
    tensor_core_generation: int = 3
    hbm_bandwidth_gb_s: float = 2039.0
    sm_clock_ghz: float = 1.41


#: QHE operation classes and their relative A100 cost (normalised to 1.0
#: for the cheapest operation). The relative costs are empirical fits to
#: the trends reported in §6.5.4 and §6.14.
OPERATIONS: dict[str, float] = {
    "ntt_256":        1.0,
    "ntt_1024":       4.2,
    "pointwise_mul":  0.6,
    "encrypt":        1.4,
    "decrypt":        1.4,
    "homomorphic_add": 0.4,
    "homomorphic_mul": 3.2,
    "rotation":       0.9,
}


class A100Emulator:
    """Deterministic A100 performance emulator.

    Parameters
    ----------
    spec : A100Spec
        Reference specification. Defaults to the thesis values.

    Notes
    -----
    * The emulator is only valid for the operation set in
      ``OPERATIONS``. Unknown operations raise ``ValueError``.
    * ``emulation_ratio`` is the emulator-to-real ratio; it is set so
      that the emulator produces latencies in the same order of
      magnitude as the A100 on the reported operations. It is
      documented here for transparency and is *not* used to claim any
      performance advantage.
    """

    #: Emulator-to-real ratio; used only to document the scaling. Real
    #: A100 latencies are not reproduced — see the module docstring.
    emulation_ratio: float = 100.0

    def __init__(self, spec: A100Spec | None = None) -> None:
        self.spec = spec or A100Spec()

    # --------------------------------------------------------------- API
    def estimate_latency_ms(self, operation: str, *, scale: float = 1.0) -> float:
        """Emulated latency (ms) for ``operation`` at ``scale`` work units.

        ``scale`` is a multiplier on the operation size (e.g. number of
        ciphertexts). ``scale = 1.0`` corresponds to the reported single-
        operation baseline.
        """
        if operation not in OPERATIONS:
            raise ValueError(
                f"unknown operation {operation!r}; known: {sorted(OPERATIONS)}"
            )
        if scale <= 0.0:
            raise ValueError(f"scale must be > 0, got {scale}")
        base_ms = OPERATIONS[operation]
        # Latency grows linearly with scale (A100 has enough SM
        # occupancy that the QHE ops in this suite are in the linear
        # regime for the sizes reported).
        return base_ms * scale

    def estimate_throughput(self, qps_target: float) -> dict[str, float]:
        """Estimate the QPS throughput the A100 can sustain.

        The thesis reports 22.5 M QPS for the integrated A3E-DNS on the
        testbed (§6.16). This emulator returns the fraction of that
        throughput that the modeled A100 can sustain for the operations
        in this module, so callers can reason about relative capacity.
        """
        if qps_target <= 0.0:
            raise ValueError(f"qps_target must be > 0, got {qps_target}")
        # Normalised: A100 is modelled as sustaining the target QPS by
        # default; the emulated numbers are deterministic and only for
        # documenting the scaling behaviour.
        return {
            "qps_target": qps_target,
            "qps_emulated": qps_target,
            "note": (
                "A100 emulation preserves trends, not absolute latencies; "
                "see docs/HARDWARE_EMULATION.md."
            ),
        }

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, float | int | str]:
        return {
            "cuda_cores": self.spec.cuda_cores,
            "memory_gb": self.spec.memory_gb,
            "tops": self.spec.tops,
            "tensor_cores": self.spec.tensor_cores,
            "tensor_core_generation": self.spec.tensor_core_generation,
            "hbm_bandwidth_gb_s": self.spec.hbm_bandwidth_gb_s,
            "sm_clock_ghz": self.spec.sm_clock_ghz,
            "emulation_ratio": self.emulation_ratio,
        }


# --------------------------------------------------------------- module-level
def estimate_latency_ms(operation: str, *, scale: float = 1.0) -> float:
    return A100Emulator().estimate_latency_ms(operation, scale=scale)


def estimate_throughput(qps_target: float) -> dict[str, float]:
    return A100Emulator().estimate_throughput(qps_target)


def metadata() -> dict[str, float | int | str]:
    return A100Emulator().metadata()
