"""DNS-over-HTTPS (DoH) adapter — HTTP/2 and HTTP/3.

Recognises DoH traffic by:

    * port 443 on both endpoints (per RFC 8484), and
    * ``content-type: application/dns-message`` in the HTTP/2 HEADERS
      frame (HTTP/2 encapsulation) or
    * HTTP/3 frame types on a QUIC connection whose ALPN includes ``h3``
      (HTTP/3 encapsulation, RFC 9114).

Produces a fixed-length feature vector whose layout is described in
``FEATURE_NAMES``. The vector is built only from observable metadata;
no payload decryption is attempted.
"""

from __future__ import annotations

import numpy as np

from src.protocols.base_adapter import PacketMetadata, Protocol, ProtocolAdapter, ProtocolFeatures

__all__ = ["DoHAdapter", "DOH_FEATURE_NAMES", "DOH_FEATURE_DIM"]

DOH_FEATURE_NAMES: tuple[str, ...] = (
    "log_payload_length",       # log1p(payload_length) — scale-invariant
    "is_http2",                 # 1 if HTTP/2 frame type present
    "is_http3",                 # 1 if HTTP/3 frame type present
    "http2_headers",            # 1 if HTTP/2 frame type == 1 (HEADERS)
    "http2_data",               # 1 if HTTP/2 frame type == 0 (DATA)
    "tls13_negotiated",         # 1 if tls_version == "TLSv1.3"
    "cipher_suite_slot",        # categorical slot; -1 if unknown
    "sni_present",              # 1 if SNI is present
    "alpn_h2",                  # 1 if "h2" in ALPN
    "alpn_h3",                  # 1 if "h3" in ALPN
)
DOH_FEATURE_DIM: int = len(DOH_FEATURE_NAMES)

# Stable slot map for the cipher-suite categorical feature. The map is
# intentionally small; unknown suites map to -1. The slot order is part
# of the reproducibility contract and must not change without bumping the
# artifact version.
_CIPHER_SLOTS: dict[str, int] = {
    "TLS_AES_128_GCM_SHA256":       0,
    "TLS_AES_256_GCM_SHA384":       1,
    "TLS_CHACHA20_POLY1305_SHA256": 2,
    "TLS_AES_128_CCM_SHA256":       3,
    "TLS_AES_128_CCM_8_SHA256":     4,
}


class DoHAdapter(ProtocolAdapter):
    """Adapter for DNS-over-HTTPS (HTTP/2 and HTTP/3)."""

    protocol = Protocol.DOH
    feature_dim = DOH_FEATURE_DIM
    FEATURE_NAMES = DOH_FEATURE_NAMES

    # --------------------------------------------------------------- support
    def supports(self, meta: PacketMetadata) -> bool:
        """Return ``True`` for DoH traffic."""
        if meta.dst_port != 443 and meta.src_port != 443:
            return False
        # HTTP/2 frame type or HTTP/3 frame type present.
        if meta.http2_frame_type is not None:
            return True
        if meta.http3_frame_type is not None:
            return True
        # Fallback: TLS 1.3 handshake with h2 or h3 ALPN.
        if meta.tls_version == "TLSv1.3" and meta.alpn:
            return any(a in meta.alpn for a in ("h2", "h3"))
        return False

    # --------------------------------------------------------------- extract
    def extract(self, meta: PacketMetadata) -> ProtocolFeatures:
        if not self.supports(meta):
            raise ValueError(
                f"packet does not look like DoH: "
                f"port={meta.dst_port}, h2={meta.http2_frame_type}, "
                f"h3={meta.http3_frame_type}, alpn={meta.alpn}"
            )

        is_http2 = 1.0 if meta.http2_frame_type is not None else 0.0
        is_http3 = 1.0 if meta.http3_frame_type is not None else 0.0
        http2_headers = 1.0 if meta.http2_frame_type == 1 else 0.0
        http2_data = 1.0 if meta.http2_frame_type == 0 else 0.0
        tls13 = 1.0 if meta.tls_version == "TLSv1.3" else 0.0
        cipher_slot = float(_CIPHER_SLOTS.get(meta.cipher_suite or "", -1))
        sni_present = 1.0 if meta.sni else 0.0
        alpn = [a.lower() for a in (meta.alpn or [])]
        alpn_h2 = 1.0 if "h2" in alpn else 0.0
        alpn_h3 = 1.0 if "h3" in alpn else 0.0

        vector = np.array(
            [
                float(np.log1p(max(meta.payload_length, 0))),
                is_http2,
                is_http3,
                http2_headers,
                http2_data,
                tls13,
                cipher_slot,
                sni_present,
                alpn_h2,
                alpn_h3,
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
