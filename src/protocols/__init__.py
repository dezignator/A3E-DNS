"""Protocol adapters for DNS-over-HTTPS, DNS-over-TLS and DNS-over-QUIC.

Each adapter translates the wire-level metadata of one encrypted DNS
protocol into the common feature representation consumed by the
downstream pipeline. The adapters are deliberately thin: they do not
decrypt, they do not parse payloads, and they do not perform detection
themselves. The unified pipeline (§6.3.3) composes the adapters with
the rest of the framework.

Public modules:

    base_adapter       — abstract interface (ProtocolAdapter)
    doh_adapter        — DNS-over-HTTPS (HTTP/2 and HTTP/3)
    dot_adapter        — DNS-over-TLS (TLS 1.3)
    doq_adapter        — DNS-over-QUIC (QUIC v1)
    unified_pipeline   — Eq. 117: P(τ) = S_eBPF ∘ F_QHE ∘ A_FL ∘ M_sandbox
"""

from __future__ import annotations

__all__ = [
    "base_adapter",
    "doh_adapter",
    "dot_adapter",
    "doq_adapter",
    "unified_pipeline",
]
