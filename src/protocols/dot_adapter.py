"""DNS-over-TLS (DoT) adapter — TLS 1.3.

Recognises DoT by:

    * port 853 on both endpoints (per RFC 7858 / RFC 8310), and
    * a TLS handshake record in the captured bytes or an explicitly
      populated ``tls_version`` field.

Produces a fixed-length feature vector whose layout is described in
``FEATURE_NAMES``. No decryption is attempted; only observable metadata
is used.
"""

from __future__ import annotations

import numpy as np

from src.protocols.base_adapter import PacketMetadata, Protocol, ProtocolAdapter, ProtocolFeatures

__all__ = ["DoTAdapter", "DOT_FEATURE_NAMES", "DOT_FEATURE_DIM"]

DOT_FEATURE_NAMES: tuple[str, ...] = (
    "log_payload_length",       # log1p(payload_length)
    "tls13_negotiated",         # 1 if tls_version == "TLSv1.3"
    "tls12_negotiated",         # 1 if tls_version == "TLSv1.2"
    "cipher_suite_slot",        # categorical slot; -1 if unknown
    "handshake_bytes_present",  # 1 if tls_handshake_bytes is not None
    "sni_present",              # 1 if SNI is present
    "port_853",                 # 1 if either endpoint uses port 853
    "record_length_mod32",      # payload_length mod 32, as a coarse signature
)
DOT_FEATURE_DIM: int = len(DOT_FEATURE_NAMES)

# Cipher-suite slot map (TLS 1.3 suites; TLS 1.2 suites intentionally
# map to -1 so that the DoT feature vector remains comparable across
# negotiated versions without re-indexing).
_CIPHER_SLOTS: dict[str, int] = {
    "TLS_AES_128_GCM_SHA256":       0,
    "TLS_AES_256_GCM_SHA384":       1,
    "TLS_CHACHA20_POLY1305_SHA256": 2,
    "TLS_AES_128_CCM_SHA256":       3,
    "TLS_AES_128_CCM_8_SHA256":     4,
}


class DoTAdapter(ProtocolAdapter):
    """Adapter for DNS-over-TLS (TLS 1.3)."""

    protocol = Protocol.DOT
    feature_dim = DOT_FEATURE_DIM
    FEATURE_NAMES = DOT_FEATURE_NAMES

    # --------------------------------------------------------------- support
    def supports(self, meta: PacketMetadata) -> bool:
        """Return ``True`` for DoT traffic."""
        if meta.dst_port != 853 and meta.src_port != 853:
            return False
        if meta.transport.lower() != "tcp":
            return False
        if meta.tls_version is None and meta.tls_handshake_bytes is None:
            return False
        return True

    # --------------------------------------------------------------- extract
    def extract(self, meta: PacketMetadata) -> ProtocolFeatures:
        if not self.supports(meta):
            raise ValueError(
                f"packet does not look like DoT: "
                f"port={meta.dst_port}, transport={meta.transport}, "
                f"tls_version={meta.tls_version}"
            )

        tls13 = 1.0 if meta.tls_version == "TLSv1.3" else 0.0
        tls12 = 1.0 if meta.tls_version == "TLSv1.2" else 0.0
        cipher_slot = float(_CIPHER_SLOTS.get(meta.cipher_suite or "", -1))
        handshake_present = 1.0 if meta.tls_handshake_bytes is not None else 0.0
        sni_present = 1.0 if meta.sni else 0.0
        port_853 = 1.0 if (meta.dst_port == 853 or meta.src_port == 853) else 0.0
        record_mod32 = float(max(meta.payload_length, 0) % 32)

        vector = np.array(
            [
                float(np.log1p(max(meta.payload_length, 0))),
                tls13,
                tls12,
                cipher_slot,
                handshake_present,
                sni_present,
                port_853,
                record_mod32,
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
