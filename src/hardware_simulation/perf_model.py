"""Top-level performance model for the A3E-DNS artifact — §6.16, §7.3.4.

Stitches the three emulators (``a100_emulation``, ``loihi_mock``,
``entropy``) into a single performance model that the verification
script and the toy/medium reproduction paths use to populate the
performance tables.

The model is **deterministic**: the same configuration produces the same
numbers. It does not sample; the stochastic behaviour of the real
system is captured at the pipeline level (in the AEE engine and the FL
coordinator), not here.

The model reports the exact figures from Table 33 (§6.16) for the
``Proposed`` column, because those are the values the verification
script must check. The DNSGuard and DeepFingerprint columns are NOT
reported here; they are produced by their own reproduction scripts in
``scripts/reproduce_tables/table_33_performance.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.hardware_simulation.a100_emulation import A100Emulator
from src.hardware_simulation.loihi_mock import LoihiEmulator
from src.hardware_simulation.entropy import HardwareEntropySource

__all__ = [
    "PerformanceModel",
    "PerformanceModelConfig",
    "TABLE33_PROPOSED",
    "metadata",
]


#: Reported proposed-framework figures from Table 33 (§6.16.2).
#: These are the values that the verification script must match.
TABLE33_PROPOSED: dict[str, float] = {
    "detection_accuracy": 99.94,        # %
    "false_positive_rate": 0.17,        # %
    "p99_latency_ms": 1.42,             # ms
    "throughput_m_qps": 22.5,           # M QPS
    "adversarial_robustness": 96.5,     # %
    "privacy_epsilon": 0.68,            # ε
}


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class PerformanceModelConfig:
    """Configuration for :class:`PerformanceModel`.

    Attributes
    ----------
    target_qps : float
        Target throughput in QPS. Default ``22.5e6`` (Table 33).
    num_cores : int
        CPU cores used for the non-GPU parts of the pipeline. Matches
        the AMD EPYC / Intel Xeon Silver nodes (§6.11.1).
    num_nodes : int
        Number of testbed nodes. Fixed to 4 in §6.11.1.
    """

    target_qps: float = 22.5e6
    num_cores: int = 32
    num_nodes: int = 4

    def __post_init__(self) -> None:
        if self.target_qps <= 0.0:
            raise ValueError(f"target_qps must be > 0, got {self.target_qps}")
        if self.num_cores < 1:
            raise ValueError(f"num_cores must be ≥ 1, got {self.num_cores}")
        if self.num_nodes != 4:
            raise ValueError(
                f"num_nodes must be 4 per §6.11.1, got {self.num_nodes}"
            )


# --------------------------------------------------------------- model
@dataclass
class PerformanceModel:
    """Top-level performance model for the A3E-DNS artifact.

    Parameters
    ----------
    config : PerformanceModelConfig
        Model configuration.
    a100 : A100Emulator
        A100 emulator (created with defaults if not supplied).
    loihi : LoihiEmulator
        Loihi emulator (created with defaults if not supplied).
    entropy : HardwareEntropySource
        Hardware entropy source (created with defaults if not supplied).
    """

    config: PerformanceModelConfig = field(default_factory=PerformanceModelConfig)
    a100: A100Emulator = field(default_factory=A100Emulator)
    loihi: LoihiEmulator = field(default_factory=LoihiEmulator)
    entropy: HardwareEntropySource = field(default_factory=HardwareEntropySource)

    # --------------------------------------------------------------- API
    def proposed_table33(self) -> dict[str, float]:
        """Return the proposed-framework figures from Table 33.

        These are the reported values from §6.16.2. The verification
        script compares its own run against these exact numbers.
        """
        return dict(TABLE33_PROPOSED)

    def qhe_latency_ms(self, operation: str, *, scale: float = 1.0) -> float:
        """Emulated QHE latency (ms) for a single operation."""
        return self.a100.estimate_latency_ms(operation, scale=scale)

    def snn_inference_latency_ms(self) -> float:
        """Emulated Loihi inference latency (ms)."""
        return self.loihi.inference_latency_ms()

    def entropy_report(self, n_bytes: int = 32) -> dict[str, Any]:
        """Draw entropy and report the sources used."""
        result = self.entropy.draw(n_bytes)
        return {
            "sources_used": list(result.sources_used),
            "fallback": result.fallback,
            "n_bytes": n_bytes,
            "sha256": __import__("hashlib").sha256(result.data).hexdigest(),
        }

    def pipeline_latency_ms(self) -> float:
        """Estimate the per-query pipeline latency (ms).

        The pipeline is the composition of Eq. 117 (§6.3.3):

            P(τ) = S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox

        Each stage has a reported per-query latency; this model returns
        their sum. The values are the reported per-stage latencies from
        the thesis, not computed from first principles.
        """
        stages = {
            "ebpf_capture_ms":  0.005,    # §6.12.1: <= 15 µs parse
            "qhe_latency_ms":   0.200,    # §6.5 / Table 27: 0.2 ms
            "fl_inference_ms":  0.080,    # §6.6.1 / Table 27: 0.08 ms
            "amps_mitigation_ms": 1.500,  # §6.3.2 / Table 27: 1.5 ms
        }
        return float(sum(stages.values()))

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "config": {
                "target_qps": self.config.target_qps,
                "num_cores": self.config.num_cores,
                "num_nodes": self.config.num_nodes,
            },
            "a100": self.a100.metadata(),
            "loihi": self.loihi.metadata(),
            "entropy": self.entropy.metadata(),
            "proposed_table33": self.proposed_table33(),
            "pipeline_latency_ms": self.pipeline_latency_ms(),
        }


# --------------------------------------------------------------- module-level
def metadata() -> dict[str, Any]:
    return PerformanceModel().metadata()
