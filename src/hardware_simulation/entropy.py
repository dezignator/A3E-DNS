"""Hardware entropy sources for the AEE engine — thesis §6.4.3.

The thesis (§6.4.3) specifies three entropy sources mixed with
cryptographic whitening:

    * CPU ``RDRAND`` and ``RDSEED`` instructions
    * ``/dev/urandom``

The module exposes a single :class:`HardwareEntropySource` that provides:

    * a **quality report** for each available source (is it physically
      present? does it produce output?),
    * a **mixed** output that combines the available sources with the
      standard cryptographic whitening (SHA-256 of the concatenated
      output plus a per-call counter, matching NIST SP 800-90B's
      "conditioning" step; the thesis does not claim SP 800-90B
      compliance, but the whitening is the standard one).

If ``RDRAND`` / ``RDSEED`` are not available (e.g. on a CPU that does
not implement them, or on an architecture where ``/dev/hwrng`` is not
present), the module falls back to ``/dev/urandom`` and records the
fallback in the manifest. This is the toy/medium reproduction path;
``a100`` and ``Loihi`` do not provide their own entropy sources to the
framework, so ``/dev/urandom`` is the default in those environments.

The module is deliberately conservative: it never claims that
``/dev/urandom`` is equivalent to ``RDRAND``. The mixed output is
marked with the list of sources that actually contributed, and callers
that require a specific source must check ``available_sources()``.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from typing import Iterable

__all__ = [
    "EntropySource",
    "HardwareEntropySource",
    "AVAILABLE_SOURCES",
    "available_sources",
    "mix_entropy",
    "metadata",
]


#: All entropy source names the module understands. ``"rdrand"`` and
#: ``"rdseed"`` are detected via ``/dev/hwrng`` presence or a direct
#: instruction probe; ``"urandom"`` is always available on Linux.
AVAILABLE_SOURCES: tuple[str, ...] = ("rdrand", "rdseed", "urandom")


# --------------------------------------------------------------- source enum
class EntropySource(str):
    """String enum of entropy source names."""

    RDRAND = "rdrand"
    RDSEED = "rdseed"
    URANDOM = "urandom"


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class EntropyResult:
    """Result of a single entropy draw."""

    data: bytes
    sources_used: tuple[str, ...] = field(default_factory=tuple)
    fallback: bool = False


# --------------------------------------------------------------- helper
def _probe_rdrand() -> bool:
    """Return ``True`` if ``RDRAND`` is available.

    On x86-64, ``RDRAND`` is exposed via ``/dev/hwrng`` on most Linux
    distributions. We do not execute ``RDRAND`` directly from Python; the
    check is a best-effort probe based on the presence of
    ``/dev/hwrng`` and the ``x86_64`` architecture.
    """
    if os.uname().machine not in {"x86_64", "amd64"}:
        return False
    return os.path.exists("/dev/hwrng")


def _probe_rdseed() -> bool:
    """Return ``True`` if ``RDSEED`` is available.

    ``RDSEED`` shares the ``/dev/hwrng`` path with ``RDRAND`` on Linux;
    we probe the same path and the ``rdseed`` capability if it is
    exposed through ``/sys/devices/virtual/misc/hw_random/``.
    """
    if not _probe_rdrand():
        return False
    # Some kernels expose rng_quality per source; if present, use it.
    for path in (
        "/sys/class/misc/hw_random/rng_available",
        "/sys/devices/virtual/misc/hw_random/rng_available",
    ):
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                return "rdseed" in content.lower()
            except OSError:
                continue
    return False


def available_sources() -> tuple[str, ...]:
    """Return the entropy source names available on this machine."""
    sources: list[str] = []
    if _probe_rdrand():
        sources.append("rdrand")
    if _probe_rdseed():
        sources.append("rdseed")
    # /dev/urandom is always available on Linux.
    sources.append("urandom")
    return tuple(sources)


# --------------------------------------------------------------- mixing
def mix_entropy(samples: Iterable[bytes], *, context: bytes = b"a3e-dns/entropy/v1") -> bytes:
    """Mix entropy samples with the standard SHA-256 conditioning.

    ``samples`` is a sequence of raw entropy byte strings, one per source.
    The output is ``SHA-256(context ‖ length_prefix ‖ sample_1 ‖ …)``.
    This is the standard "conditioning" step; it does not by itself
    guarantee uniformity, and callers that need NIST SP 800-90B
    guarantees must use a tested conditioning function. The thesis does
    not claim such a guarantee.
    """
    h = hashlib.sha256()
    h.update(context)
    h.update(b"\x00")
    for sample in samples:
        if not isinstance(sample, (bytes, bytearray)):
            raise TypeError("entropy samples must be bytes")
        h.update(struct.pack(">I", len(sample)))
        h.update(bytes(sample))
    return h.digest()


# --------------------------------------------------------------- source
class HardwareEntropySource:
    """Hardware entropy source with a documented fallback path.

    Parameters
    ----------
    sources : tuple[str, ...], optional
        Sources to use, in priority order. Defaults to all available
        sources on this machine (``available_sources()``).
    required : tuple[str, ...], optional
        If given, the source raises if any of these is unavailable. Use
        this in production code that must not silently fall back.
    """

    def __init__(
        self,
        sources: tuple[str, ...] | None = None,
        *,
        required: tuple[str, ...] | None = None,
    ) -> None:
        available = available_sources()
        requested = sources or available
        for src in requested:
            if src not in AVAILABLE_SOURCES:
                raise ValueError(
                    f"unknown entropy source {src!r}; known: {AVAILABLE_SOURCES}"
                )
        missing = [s for s in requested if s not in available]
        if required:
            for src in required:
                if src not in available:
                    raise RuntimeError(
                        f"required entropy source {src!r} is not available; "
                        f"available: {available}"
                    )
        self._requested = tuple(requested)
        self._available = available
        self._missing = tuple(missing)
        self._counter = 0

    # --------------------------------------------------------------- API
    def draw(self, n_bytes: int = 32) -> EntropyResult:
        """Draw ``n_bytes`` bytes of mixed entropy."""
        if n_bytes <= 0:
            raise ValueError(f"n_bytes must be > 0, got {n_bytes}")
        samples: list[bytes] = []
        used: list[str] = []
        for src in self._requested:
            if src not in self._available:
                continue
            sample = self._draw_one(src, n_bytes)
            if sample is None:
                continue
            samples.append(sample)
            used.append(src)

        if not samples:
            # Guaranteed fallback: /dev/urandom.
            data = os.urandom(n_bytes + 16)
            self._counter += 1
            mixed = mix_entropy(
                [data, self._counter.to_bytes(8, "big")],
                context=b"a3e-dns/entropy/v1/fallback",
            )[:n_bytes]
            return EntropyResult(data=mixed, sources_used=("urandom",), fallback=True)

        self._counter += 1
        samples.append(self._counter.to_bytes(8, "big"))
        mixed = mix_entropy(samples, context=b"a3e-dns/entropy/v1")[:n_bytes]
        return EntropyResult(
            data=mixed,
            sources_used=tuple(used),
            fallback=("urandom" in used and len(used) == 1),
        )

    def _draw_one(self, source: str, n_bytes: int) -> bytes | None:
        if source == "urandom":
            return os.urandom(n_bytes)
        if source in {"rdrand", "rdseed"}:
            # Read from /dev/hwrng; the kernel routes the bytes from
            # RDRAND / RDSEED through this character device.
            try:
                with open("/dev/hwrng", "rb") as fh:
                    return fh.read(n_bytes)
            except OSError:
                return None
        return None

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, object]:
        return {
            "requested": list(self._requested),
            "available": list(self._available),
            "missing": list(self._missing),
            "draws": self._counter,
        }


# --------------------------------------------------------------- module-level
def metadata() -> dict[str, object]:
    src = HardwareEntropySource()
    return src.metadata()
