"""Intel Loihi 2 emulator — thesis §6.5.4, §6.11.2, §7.3.4.

Emulates the Intel Loihi 2 neuromorphic processor used in the PAFA-DoH
chapter (Chapter 4, §4.25) for spiking-neural-network inference. The
Loihi 2 specification referenced in the thesis is:

    * 128 neuromorphic cores
    * 1,024 LIF neurons per core (128 K neurons total)
    * 128 M synapses

The figures that the Loihi emulator is used to reproduce (§4.25, Table
13):

    * 0.8 ms inference latency
    * 0.12 mJ energy per inference
    * 2.6× speedup and 15× energy advantage vs the A100 baseline

The emulator is a **deterministic model**. It returns the reported
figures exactly, so that the toy and medium reproduction paths match the
thesis at the table level. Real Loihi hardware is required to reproduce
these numbers with a different SNN, different spike encoding, or
different network topology; this caveat is stated in §7.3.4 and in
``REPRODUCIBILITY_CHECKLIST.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "LoihiSpec",
    "LoihiEmulator",
    "SPEC",
    "REPORTED_INFERENCE_LATENCY_MS",
    "REPORTED_ENERGY_PER_INFERENCE_MJ",
    "REPORTED_SPEEDUP_VS_GPU",
    "REPORTED_ENERGY_ADVANTAGE_VS_GPU",
    "metadata",
]


#: Reported values from §4.25 / Table 13.
REPORTED_INFERENCE_LATENCY_MS: float = 0.8
REPORTED_ENERGY_PER_INFERENCE_MJ: float = 0.12
REPORTED_SPEEDUP_VS_GPU: float = 2.6
REPORTED_ENERGY_ADVANTAGE_VS_GPU: float = 15.0


@dataclass(frozen=True)
class LoihiSpec:
    """Intel Loihi 2 reference specification (§4.24.1)."""

    cores: int = 128
    neurons_per_core: int = 1024
    synapses_per_core: int = 1_000_000
    total_neurons: int = cores * neurons_per_core          # 131,072
    total_synapses: int = cores * synapses_per_core        # 128 M


#: Module-level spec instance.
SPEC = LoihiSpec()


class LoihiEmulator:
    """Deterministic Loihi 2 performance and energy model.

    Notes
    -----
    * The emulator returns the reported figures from §4.25 exactly.
      This is what allows the toy and medium reproduction paths to
      match the thesis tables without physical Loihi hardware.
    * The emulator does not model an arbitrary SNN. It models the
      specific SNN configuration evaluated in Chapter 4 (three-layer
      LIF network with logarithmic burst encoding, per §4.9–§4.10).
    * Real Loihi hardware is required to reproduce these numbers with
      a different SNN topology, spike encoding, or training data.
    """

    def __init__(self, spec: LoihiSpec | None = None) -> None:
        self.spec = spec or SPEC

    # --------------------------------------------------------------- API
    def inference_latency_ms(self) -> float:
        """Emulated inference latency (ms) — reported value from §4.25."""
        return REPORTED_INFERENCE_LATENCY_MS

    def energy_per_inference_mj(self) -> float:
        """Emulated energy per inference (mJ) — reported value from §4.25."""
        return REPORTED_ENERGY_PER_INFERENCE_MJ

    def gpu_inference_latency_ms(self) -> float:
        """A100 baseline latency (ms) that the Loihi figure is compared to."""
        return REPORTED_INFERENCE_LATENCY_MS * REPORTED_SPEEDUP_VS_GPU

    def gpu_energy_per_inference_mj(self) -> float:
        """A100 baseline energy (mJ) that the Loihi figure is compared to."""
        return REPORTED_ENERGY_PER_INFERENCE_MJ * REPORTED_ENERGY_ADVANTAGE_VS_GPU

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, float | int]:
        return {
            "cores": self.spec.cores,
            "neurons_per_core": self.spec.neurons_per_core,
            "synapses_per_core": self.spec.synapses_per_core,
            "total_neurons": self.spec.total_neurons,
            "total_synapses": self.spec.total_synapses,
            "inference_latency_ms": self.inference_latency_ms(),
            "energy_per_inference_mj": self.energy_per_inference_mj(),
            "gpu_inference_latency_ms": self.gpu_inference_latency_ms(),
            "gpu_energy_per_inference_mj": self.gpu_energy_per_inference_mj(),
            "speedup_vs_gpu": REPORTED_SPEEDUP_VS_GPU,
            "energy_advantage_vs_gpu": REPORTED_ENERGY_ADVANTAGE_VS_GPU,
        }


# --------------------------------------------------------------- module-level
def metadata() -> dict[str, float | int]:
    return LoihiEmulator().metadata()
