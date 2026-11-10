"""DNS-over-QUIC (DoQ) adapter — QUIC v1.

Recognises DoQ by:

    * transport ``udp``, and
    * a QUIC version field with the v1 wire value (``0x00000001``) or a
      non-``None`` ``quic_connection_id``, and
    * either port 853/udp or an ALPN containing ``doq``.

Produces a fixed-length feature vector whose layout is described in
``FEATURE_NAMES``. No decryption is attempted.
"""

from __future__ import annotations

import numpy as np

from src.protocols.base_adapter import PacketMetadata, Protocol, ProtocolAdapter, ProtocolFeatures

__all__ = ["DoQAdapter", "DOQ_FEATURE_NAMES", "DOQ_FEATURE_DIM", "QUIC_V1"]

#: QUIC v1 version field per RFC 9000.
QUIC_V1: int = 0x00000001

DOQ_FEATURE_NAMES: tuple[str, ...] = (
    "log_payload_length",       # log1p(payload_length)
    "quic_v1",                  # 1 if quic_version == QUIC_V1
    "quic_v2_or_other",         # 1 if quic_version is not None and != QUIC_V1
    "cid_present",              # 1 if quic_connection_id is not None
    "cid_length_mod8",          # len(quic_connection_id) % 8, coarse signature
    "alpn_doq",                 # 1 if "doq" in ALPN
    "port_853",                 # 1 if either endpoint uses port 853
    "udp_transport",            # 1 if transport == "udp"
)
DOQ_FEATURE_DIM: int = len(DOQ_FEATURE_NAMES)


class DoQAdapter(ProtocolAdapter):
    """Adapter for DNS-over-QUIC (QUIC v1)."""

    protocol = Protocol.DOQ
    feature_dim = DOQ_FEATURE_DIM
    FEATURE_NAMES = DOQ_FEATURE_NAMES

    # --------------------------------------------------------------- support
    def supports(self, meta: PacketMetadata) -> bool:
        """Return ``True`` for DoQ traffic."""
        if meta.transport.lower() != "udp":
            return False
        if meta.quic_version == QUIC_V1 or meta.quic_connection_id is not None:
            return True
        if meta.dst_port == 853 or meta.src_port == 853:
            return True
        if meta.alpn and any(a.lower() == "doq" for a in meta.alpn):
            return True
        return False

    # --------------------------------------------------------------- extract
    def extract(self, meta: PacketMetadata) -> ProtocolFeatures:
        if not self.supports(meta):
            raise ValueError(
                f"packet does not look like DoQ: "
                f"transport={meta.transport}, quic_version={meta.quic_version}, "
                f"cid={meta.quic_connection_id is not None}"
            )

        quic_v1 = 1.0 if meta.quic_version == QUIC_V1 else 0.0
        quic_other = 1.0 if (meta.quic_version is not None and meta.quic_version != QUIC_V1) else 0.0
        cid_present = 1.0 if meta.quic_connection_id is not None else 0.0
        cid_len_mod8 = float(len(meta.quic_connection_id) % 8) if meta.quic_connection_id is not None else -1.0
        alpn = [a.lower() for a in (meta.alpn or [])]
        alpn_doq = 1.0 if "doq" in alpn else 0.0
        port_853 = 1.0 if (meta.dst_port == 853 or meta.src_port == 853) else 0.0
        udp = 1.0 if meta.transport.lower() == "udp" else 0.0

        vector = np.array(
            [
                float(np.log1p(max(meta.payload_length, 0))),
                quic_v1,
                quic_other,
                cid_present,
                cid_len_mod8,
                alpn_doq,
                port_853,
                udp,
            ],
            dtype=np.float64,
        )

        return ProtocolFeatures(
            protocol=self.protocol,
            vector=vector,
            timestamp=meta.timestamp,
            flow_key=self.flow_key(meta),
            source=meta,
        )
