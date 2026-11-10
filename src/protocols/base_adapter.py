"""Abstract protocol adapter interface.

Every encrypted-DNS protocol adapter must expose the same surface so
that the unified pipeline (§6.3.3, Eq. 117) can compose them without
branching on the protocol. An adapter reads an already-captured packet
or flow record (bytes + metadata) and produces a ``ProtocolFeatures``
record; it does **not** decrypt, and it does **not** inspect payloads.

The record is deliberately transport-agnostic. The only protocol-specific
fields are the ones that genuinely differ between DoH, DoT and DoQ, and
even those are normalised to a common shape so that downstream models do
not need to special-case the protocol.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping

import numpy as np

__all__ = [
    "Protocol",
    "PacketMetadata",
    "ProtocolFeatures",
    "ProtocolAdapter",
]


# --------------------------------------------------------------- protocol enum
class Protocol(str, Enum):
    """The three encrypted-DNS protocols covered by the thesis."""

    DOH = "doh"
    DOT = "dot"
    DOQ = "doq"


# --------------------------------------------------------------- input record
@dataclass(frozen=True)
class PacketMetadata:
    """Transport-agnostic packet/flow metadata.

    Every adapter consumes the same record; the adapter is responsible for
    deciding which fields are meaningful for its protocol. Fields that do
    not apply are set to ``None`` and must be ignored by the adapter.

    Attributes
    ----------
    timestamp : float
        Seconds since the epoch, at the granularity of the capture
        (``~1 µs`` per §6.3.3 for the deployed testbed).
    src_ip, dst_ip : str
        Source / destination IPv4 or IPv6 address.
    src_port, dst_port : int
        Source / destination transport port.
    transport : str
        ``"tcp"`` or ``"udp"``.
    payload_length : int
        Length of the encrypted application payload, in bytes. This is
        what the adapter sees; it is **not** the plaintext DNS message
        length.
    tls_handshake_bytes : bytes | None
        Raw TLS handshake bytes if the packet is part of a TLS handshake
        (DoT always; DoH over HTTP/2 always; DoH over HTTP/3 and DoQ only
        on the initial QUIC handshake). ``None`` otherwise.
    tls_version : str | None
        Negotiated TLS version, e.g. ``"TLSv1.3"``.
    cipher_suite : str | None
        Negotiated cipher suite, e.g. ``"TLS_AES_128_GCM_SHA256"``.
    http2_frame_type : int | None
        HTTP/2 frame type (1=HEADERS, 0=DATA, etc.), if applicable.
    http3_frame_type : int | None
        HTTP/3 frame type, if applicable.
    quic_connection_id : bytes | None
        QUIC connection ID, if applicable.
    quic_version : int | None
        QUIC version field, if applicable (``0x00000001`` = v1).
    sni : str | None
        Server Name Indication from the TLS handshake, if present.
    alpn : list[str] | None
        ALPN protocols offered by the client.
    raw : bytes | None
        Raw captured bytes, when available. Adapters that do not need
        them must ignore this field.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    payload_length: int

    tls_handshake_bytes: bytes | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    http2_frame_type: int | None = None
    http3_frame_type: int | None = None
    quic_connection_id: bytes | None = None
    quic_version: int | None = None
    sni: str | None = None
    alpn: list[str] | None = None

    raw: bytes | None = None


# --------------------------------------------------------------- output record
@dataclass(frozen=True)
class ProtocolFeatures:
    """Protocol-agnostic feature record produced by every adapter.

    The feature vector is ``vector``; ``protocol`` identifies which adapter
    produced it, and ``source`` identifies the metadata record it came
    from. ``raw_metadata`` is retained for traceability and for the
    anomaly detector's explanation outputs; it is **never** sent over the
    wire to the FL coordinator.

    Attributes
    ----------
    protocol : Protocol
    vector : np.ndarray
        Feature vector of fixed length ``feature_dim``. The layout is
        documented in the ``FEATURE_NAMES`` class attribute of each
        concrete adapter.
    timestamp : float
        Timestamp of the originating packet.
    flow_key : str
        Stable identifier of the 5-tuple, used for per-flow state in AMPS.
    source : PacketMetadata
        The input record, retained for traceability.
    """

    protocol: Protocol
    vector: np.ndarray
    timestamp: float
    flow_key: str
    source: PacketMetadata = field(repr=False)

    def __post_init__(self) -> None:
        if self.vector.ndim != 1:
            raise ValueError(f"vector must be 1-D, got shape {self.vector.shape}")
        if self.vector.size == 0:
            raise ValueError("vector must be non-empty")


# --------------------------------------------------------------- adapter ABC
class ProtocolAdapter(ABC):
    """Abstract protocol adapter.

    Subclasses implement :meth:`supports` and :meth:`extract`. The base
    class provides :meth:`flow_key` and the ``feature_dim`` contract used
    by the unified pipeline.
    """

    #: Protocol handled by this adapter.
    protocol: Protocol

    #: Length of the feature vector produced by :meth:`extract`.
    feature_dim: int

    #: Human-readable name of each feature slot in the produced vector.
    #: Must have length ``feature_dim``.
    FEATURE_NAMES: tuple[str, ...]

    # --------------------------------------------------------------- contract
    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        for attr in ("protocol", "feature_dim", "FEATURE_NAMES"):
            if not hasattr(cls, attr):
                raise TypeError(f"{cls.__name__} must define class attribute {attr!r}")
        if len(cls.FEATURE_NAMES) != cls.feature_dim:
            raise TypeError(
                f"{cls.__name__}.FEATURE_NAMES has length {len(cls.FEATURE_NAMES)} "
                f"but feature_dim is {cls.feature_dim}"
            )

    # --------------------------------------------------------------- API
    @abstractmethod
    def supports(self, meta: PacketMetadata) -> bool:
        """Return ``True`` if this adapter can handle ``meta``.

        The unified pipeline calls ``supports`` on each adapter in order
        and dispatches to the first one that returns ``True``.
        """

    @abstractmethod
    def extract(self, meta: PacketMetadata) -> ProtocolFeatures:
        """Convert a metadata record into a feature record.

        Must not raise on valid packets; callers are expected to have
        already used :meth:`supports`.
        """

    # --------------------------------------------------------------- helpers
    def flow_key(self, meta: PacketMetadata) -> str:
        """Stable 5-tuple flow key.

        The order is (src_ip, src_port, dst_ip, dst_port, transport), and
        the fields are joined with ``|``. Endpoints are not canonicalised
        (i.e. the key is direction-sensitive), which matches the thesis's
        treatment of unidirectional flows in the telemetry.
        """
        return "|".join(
            (
                meta.src_ip,
                str(meta.src_port),
                meta.dst_ip,
                str(meta.dst_port),
                meta.transport.lower(),
            )
        )

    def metadata(self) -> Mapping[str, Any]:
        """Return adapter metadata used by the reproducibility manifest."""
        return {
            "protocol": self.protocol.value,
            "feature_dim": self.feature_dim,
            "feature_names": list(self.FEATURE_NAMES),
        }
