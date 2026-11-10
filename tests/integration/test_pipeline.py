"""Integration tests for the unified pipeline (Eq. 117, §6.3.3).

Covers:
    * the composition ``S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox``,
    * the adapter dispatch order,
    * the shape contracts at each stage,
    * the error path when no adapter supports a packet.

These are CPU-only tests. They do not exercise the emulated A100 /
Loihi / BMv2, which is exercised by ``tests/integration/test_end_to_end.py``.
"""

from __future__ import annotations

import numpy as np
import pytest

from src.protocols.base_adapter import PacketMetadata, Protocol
from src.protocols.doh_adapter import DoHAdapter
from src.protocols.dot_adapter import DoTAdapter
from src.protocols.doq_adapter import DoQAdapter
from src.protocols.unified_pipeline import (
    PipelineOperators,
    UnifiedPipeline,
    build_default_pipeline,
)


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def doh_packet() -> PacketMetadata:
    return PacketMetadata(
        timestamp=1762732800.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=443,
        transport="tcp",
        payload_length=512,
        http2_frame_type=1,
        tls_version="TLSv1.3",
        alpn=["h2"],
        sni="doh.example.com",
    )


@pytest.fixture
def dot_packet() -> PacketMetadata:
    return PacketMetadata(
        timestamp=1762732801.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50001,
        dst_port=853,
        transport="tcp",
        payload_length=256,
        tls_version="TLSv1.3",
        tls_handshake_bytes=b"\x16\x03\x03\x00\x10",
    )


@pytest.fixture
def doq_packet() -> PacketMetadata:
    return PacketMetadata(
        timestamp=1762732802.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50002,
        dst_port=853,
        transport="udp",
        payload_length=128,
        quic_connection_id=b"\x01\x02\x03\x04",
        quic_version=0x00000001,
        alpn=["doq"],
    )


# ---------------------------------------------------------------- adapter dispatch
def test_doh_adapter_supports_doh(doh_packet):
    assert DoHAdapter().supports(doh_packet)


def test_doh_adapter_rejects_dot(dot_packet):
    assert not DoHAdapter().supports(dot_packet)


def test_dot_adapter_supports_dot(dot_packet):
    assert DoTAdapter().supports(dot_packet)


def test_doq_adapter_supports_doq(doq_packet):
    assert DoQAdapter().supports(doq_packet)


# ---------------------------------------------------------------- feature extraction
def test_doh_adapter_extracts_features(doh_packet):
    features = DoHAdapter().extract(doh_packet)
    assert features.protocol == Protocol.DOH
    assert features.vector.shape == (DoHAdapter.feature_dim,)


def test_dot_adapter_extracts_features(dot_packet):
    features = DoTAdapter().extract(dot_packet)
    assert features.protocol == Protocol.DOT
    assert features.vector.shape == (DoTAdapter.feature_dim,)


def test_doq_adapter_extracts_features(doq_packet):
    features = DoQAdapter().extract(doq_packet)
    assert features.protocol == Protocol.DOQ
    assert features.vector.shape == (DoQAdapter.feature_dim,)


def test_adapter_rejects_unsupported_packet(doq_packet):
    with pytest.raises(ValueError):
        DoHAdapter().extract(doq_packet)


# ---------------------------------------------------------------- pipeline
def test_pipeline_selects_first_matching_adapter(doh_packet, dot_packet, doq_packet):
    pipeline = build_default_pipeline()
    assert pipeline.select_adapter(doh_packet).protocol == Protocol.DOH
    assert pipeline.select_adapter(dot_packet).protocol == Protocol.DOT
    assert pipeline.select_adapter(doq_packet).protocol == Protocol.DOQ


def test_pipeline_rejects_unknown_packet():
    packet = PacketMetadata(
        timestamp=0.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1,
        dst_port=9999,
        transport="tcp",
        payload_length=10,
    )
    pipeline = build_default_pipeline()
    with pytest.raises(ValueError):
        pipeline.select_adapter(packet)


def test_pipeline_run_empty_returns_empty():
    pipeline = build_default_pipeline()
    assert pipeline.run([]) == []


# ---------------------------------------------------------------- run with custom operators
def test_pipeline_run_with_custom_operators(doh_packet):
    """A pipeline with a trivial ``F_QHE`` (identity), a trivial ``A_FL``
    (scores = 0.5), and a trivial ``M_sandbox`` (no mitigation) should
    run without error and return one record per packet."""

    def ebpf(packets):
        return [DoHAdapter().extract(p) for p in packets]

    def qhe(x):
        return x

    def fl(x):
        return np.full(x.shape[0], 0.5)

    def sandbox(features, scores, keys):
        return [
            {"flow_key": k, "score": float(s), "mitigated": False}
            for k, s in zip(keys, scores)
        ]

    pipeline = UnifiedPipeline(
        adapters=(DoHAdapter(),),
        operators=PipelineOperators(ebpf=ebpf, qhe=qhe, fl=fl, sandbox=sandbox),
    )
    results = pipeline.run([doh_packet, doh_packet])
    assert len(results) == 2
    for r in results:
        assert "flow_key" in r
        assert "score" in r
        assert "mitigated" in r


# ---------------------------------------------------------------- shape contracts
def test_pipeline_rejects_wrong_qhe_shape(doh_packet):
    def ebpf(packets):
        return [DoHAdapter().extract(p) for p in packets]

    def qhe(x):
        return x[:-1]  # wrong shape: drop a row

    def fl(x):
        return np.zeros(x.shape[0])

    def sandbox(features, scores, keys):
        return [{} for _ in keys]

    pipeline = UnifiedPipeline(
        adapters=(DoHAdapter(),),
        operators=PipelineOperators(ebpf=ebpf, qhe=qhe, fl=fl, sandbox=sandbox),
    )
    with pytest.raises(RuntimeError, match="F_QHE"):
        pipeline.run([doh_packet])


def test_pipeline_rejects_wrong_fl_shape(doh_packet):
    def ebpf(packets):
        return [DoHAdapter().extract(p) for p in packets]

    def qhe(x):
        return x

    def fl(x):
        return np.zeros(x.shape[0] + 1)  # one too many scores

    def sandbox(features, scores, keys):
        return [{} for _ in keys]

    pipeline = UnifiedPipeline(
        adapters=(DoHAdapter(),),
        operators=PipelineOperators(ebpf=ebpf, qhe=qhe, fl=fl, sandbox=sandbox),
    )
    with pytest.raises(RuntimeError, match="A_FL"):
        pipeline.run([doh_packet])


# ---------------------------------------------------------------- guardrails
def test_pipeline_rejects_empty_adapters():
    with pytest.raises(ValueError):
        UnifiedPipeline(
            adapters=(),
            operators=PipelineOperators(ebpf=lambda x: x),
        )


def test_pipeline_rejects_duplicate_adapters():
    with pytest.raises(ValueError):
        UnifiedPipeline(
            adapters=(DoHAdapter(), DoHAdapter()),
            operators=PipelineOperators(ebpf=lambda x: x),
        )
