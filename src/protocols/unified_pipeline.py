"""Unified multi-protocol processing pipeline — thesis Eq. 117, §6.3.3.

The pipeline composes four stages in a fixed order:

    P(τ) = S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox        (Eq. 117)

where:

    * ``S_eBPF``     — kernel-level packet capture and protocol identification
                       (§6.12, the P4/eBPF data plane).
    * ``F_QHE``      — homomorphic feature transformation (§6.5).
    * ``A_FL``       — federated anomaly detection (§6.6).
    * ``M_sandbox``  — protocol-aware isolation in the AMPS sandbox (§6.3.2).

Each operator is **Lipschitz-stable** (Eq. 118):

    ‖O_i(τ) − O_i(τ′)‖ ≤ L_i · ‖τ − τ′‖ + ε_i

This module only wires the operators; the operator implementations live
in their respective subpackages. Adapters are selected by the first one
that ``supports(meta)``; the pipeline raises if none does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

import numpy as np

from src.protocols.base_adapter import (
    PacketMetadata,
    ProtocolAdapter,
    ProtocolFeatures,
)
from src.protocols.doh_adapter import DoHAdapter
from src.protocols.dot_adapter import DoTAdapter
from src.protocols.doq_adapter import DoQAdapter

__all__ = [
    "PipelineOperators",
    "UnifiedPipeline",
    "build_default_pipeline",
]


# --------------------------------------------------------------- operators
@dataclass
class PipelineOperators:
    """The four operators of Eq. 117, injected by the caller.

    Each operator is a callable ``(x) -> y``; the pipeline only requires
    that the four calls compose in the documented order. This keeps the
    pipeline testable without importing the heavyweight operator
    implementations.

    Attributes
    ----------
    ebpf : callable
        ``S_eBPF``. Accepts an iterable of :class:`PacketMetadata` and
        returns an iterable of :class:`ProtocolFeatures`. Typically the
        default is a pass-through over the adapters.
    qhe : callable
        ``F_QHE``. Accepts an array of features and returns a transformed
        array. In the default pipeline this is the identity; the real
        operator is installed by the QHE module.
    fl : callable
        ``A_FL``. Accepts a feature array and returns per-sample anomaly
        scores in [0, 1]. The real operator is installed by the FL module.
    sandbox : callable
        ``M_sandbox``. Accepts (feature, score, flow_key) tuples and
        returns the mitigation decision. The real operator is installed
        by the AMPS module.
    """

    ebpf: callable
    qhe: callable = field(default=lambda x: x)
    fl: callable = field(default=lambda x: np.zeros(len(x), dtype=np.float64))
    sandbox: callable = field(
        default=lambda features, scores, flow_keys: [
            {"flow_key": k, "score": float(s), "mitigated": False}
            for k, s in zip(flow_keys, scores)
        ]
    )


# --------------------------------------------------------------- pipeline
@dataclass
class UnifiedPipeline:
    """The composed pipeline of Eq. 117.

    Parameters
    ----------
    adapters : Sequence[ProtocolAdapter]
        Adapters in dispatch order. The first one whose ``supports`` returns
        ``True`` wins. The default order is ``[DoHAdapter, DoTAdapter, DoQAdapter]``;
        DoH is tried first because it is the most widely deployed protocol
        (§6.1) and the cheapest to recognise.
    operators : PipelineOperators
        The four operators.
    """

    adapters: Sequence[ProtocolAdapter]
    operators: PipelineOperators

    def __post_init__(self) -> None:
        if not self.adapters:
            raise ValueError("adapters must be non-empty")
        self._protocols = tuple(a.protocol.value for a in self.adapters)
        if len(set(self._protocols)) != len(self._protocols):
            raise ValueError(f"duplicate protocols in adapters: {self._protocols}")

    # --------------------------------------------------------------- dispatch
    def select_adapter(self, meta: PacketMetadata) -> ProtocolAdapter:
        """Return the first adapter whose ``supports`` returns ``True``."""
        for adapter in self.adapters:
            if adapter.supports(meta):
                return adapter
        raise ValueError(
            "no adapter supports the packet: "
            f"transport={meta.transport}, dst_port={meta.dst_port}, "
            f"quic_version={meta.quic_version}"
        )

    def features_of(self, packet: PacketMetadata) -> ProtocolFeatures:
        """Extract features for a single packet."""
        return self.select_adapter(packet).extract(packet)

    # --------------------------------------------------------------- run
    def run(self, packets: Iterable[PacketMetadata]) -> list[dict]:
        """Apply Eq. 117 to a stream of packets.

        The output is a list of mitigation records, one per packet, as
        produced by the ``M_sandbox`` operator. Records that were not
        mitigated by the sandbox are still returned, with
        ``"mitigated": False``, so that downstream consumers can compute
        the full distribution of scores.
        """
        packet_list = list(packets)
        if not packet_list:
            return []

        # Stage 1 — S_eBPF
        features: list[ProtocolFeatures] = self.operators.ebpf(packet_list)
        if len(features) != len(packet_list):
            raise RuntimeError(
                f"S_eBPF produced {len(features)} features for {len(packet_list)} packets"
            )

        # Stage 2 — F_QHE (identity by default; real operator replaces it)
        stacked = np.stack([f.vector for f in features], axis=0)
        transformed = self.operators.qhe(stacked)
        transformed = np.asarray(transformed, dtype=np.float64)
        if transformed.shape != stacked.shape:
            raise RuntimeError(
                f"F_QHE produced shape {transformed.shape}, expected {stacked.shape}"
            )

        # Stage 3 — A_FL
        scores = np.asarray(self.operators.fl(transformed), dtype=np.float64).ravel()
        if scores.shape[0] != len(features):
            raise RuntimeError(
                f"A_FL produced {scores.shape[0]} scores for {len(features)} features"
            )

        # Stage 4 — M_sandbox
        flow_keys = [f.flow_key for f in features]
        mitigations = list(self.operators.sandbox(transformed, scores, flow_keys))
        if len(mitigations) != len(features):
            raise RuntimeError(
                f"M_sandbox produced {len(mitigations)} decisions for {len(features)} features"
            )
        return mitigations


# --------------------------------------------------------------- factory
def _default_ebpf(packets: Sequence[PacketMetadata]) -> list[ProtocolFeatures]:
    """Default ``S_eBPF``: dispatch each packet through the adapters."""
    adapters = (DoHAdapter(), DoTAdapter(), DoQAdapter())
    out: list[ProtocolFeatures] = []
    for meta in packets:
        for adapter in adapters:
            if adapter.supports(meta):
                out.append(adapter.extract(meta))
                break
        else:
            raise ValueError(f"no adapter supports packet with dst_port={meta.dst_port}")
    return out


def build_default_pipeline(
    *,
    operators: PipelineOperators | None = None,
) -> UnifiedPipeline:
    """Build a pipeline with the default adapters and, optionally, custom operators.

    Parameters
    ----------
    operators : PipelineOperators, optional
        If ``None``, a pipeline with the identity QHE operator, a zero
        FL operator, and a non-mitigating sandbox is returned. This is
        the wiring used by the toy/medium modes before the real operators
        are injected.
    """
    adapters = (DoHAdapter(), DoTAdapter(), DoQAdapter())
    if operators is None:
        operators = PipelineOperators(ebpf=_default_ebpf)
    elif operators.ebpf is None:  # type: ignore[truthy-function]
        operators.ebpf = _default_ebpf
    return UnifiedPipeline(adapters=adapters, operators=operators)
