"""eBPF / XDP packet-capture loader — thesis §6.11.2, §6.12.

Loads an XDP filter into the kernel at the driver level, before the
kernel network stack, so that encrypted-DNS packet capture happens at
line rate with minimal CPU overhead. The loader uses the ``bpf()``
syscall via the ``bcc`` Python bindings when they are available, and
falls back to a documented simulation when they are not.

The XDP source is ``src/dataplane/ebpf_capture.c``. The capture policy
(in the source file) filters on the resolver ports:

    tcp port 443      → DoH
    tcp port 853      → DoT
    udp port 853      → DoQ

This module is the **loader**; the capture policy is in the C source.
The filter is a published eBPF pattern; the contribution is the specific
filter for encrypted-DNS metadata extraction, not the eBPF framework
itself (§6.12, ``docs/LIMITATIONS.md``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "EBPFConfig",
    "EBPFLoader",
    "EBPFLoadError",
    "EBPFSourceMissing",
    "CAPTURE_PORTS",
]

#: Ports captured by the XDP filter, per §6.11.2 / §6.12.
CAPTURE_PORTS: tuple[tuple[str, int], ...] = (
    ("tcp", 443),   # DoH
    ("tcp", 853),   # DoT
    ("udp", 853),   # DoQ
)


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class EBPFConfig:
    """Configuration for :class:`EBPFLoader`.

    Attributes
    ----------
    source_path : Path
        Path to ``ebpf_capture.c``.
    interface : str
        Network interface to attach the XDP program to.
    mode : {"skb", "driver"}
        XDP attach mode. ``"skb"`` is the generic (software) path and
        works on any driver; ``"driver"`` requires native XDP support.
    pin_path : str | None
        Optional BPF filesystem path to pin the program at.
    """

    source_path: Path = Path("src/dataplane/ebpf_capture.c")
    interface: str = "eth0"
    mode: str = "skb"
    pin_path: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"skb", "driver"}:
            raise ValueError(f"mode must be 'skb' or 'driver', got {self.mode!r}")
        if not self.interface:
            raise ValueError("interface must be non-empty")


# --------------------------------------------------------------- errors
class EBPFLoadError(RuntimeError):
    """Raised when the XDP program fails to load."""


class EBPFSourceMissing(FileNotFoundError):
    """Raised when the eBPF C source is not present."""


# --------------------------------------------------------------- loader
class EBPFLoader:
    """Loads and manages the XDP capture filter.

    Parameters
    ----------
    config : EBPFConfig
        Loader configuration.

    Notes
    -----
    * Loading requires ``CAP_BPF`` + ``CAP_NET_ADMIN`` (or root). The
      loader does not attempt to escalate privileges; it reports the
      missing capability as an :class:`EBPFLoadError`.
    * In toy and medium modes, the loader falls back to a simulation
      that writes a marker file and does not touch the kernel.
    """

    def __init__(self, config: EBPFConfig | None = None) -> None:
        self.config = config or EBPFConfig()

    # --------------------------------------------------------------- API
    def load(self) -> dict[str, Any]:
        """Load the XDP filter and return the load metadata.

        Raises
        ------
        EBPFSourceMissing
            If the C source is missing.
        EBPFLoadError
            If the load fails.
        """
        if not self.config.source_path.exists():
            raise EBPFSourceMissing(f"missing eBPF source: {self.config.source_path}")

        # Prefer the standard xdp-loader if it is installed; fall back to
        # the bcc Python loader; fall back to simulation.
        if shutil.which("xdp-loader") is not None:
            return self._load_with_xdp_loader()
        if self._bcc_available():
            return self._load_with_bcc()
        return self._simulate()

    def unload(self) -> bool:
        """Detach the XDP program from the interface.

        Returns ``True`` if the real unload path was taken,
        ``False`` if the simulation was used.
        """
        if shutil.which("xdp-loader") is not None:
            cmd = ["xdp-loader", "unload", self.config.interface]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise EBPFLoadError(f"xdp-loader unload failed: {proc.stderr}")
            return True
        return False

    # --------------------------------------------------------------- internals
    @staticmethod
    def _bcc_available() -> bool:
        try:
            import bcc  # type: ignore  # noqa: F401
        except ImportError:
            return False
        return True

    def _load_with_xdp_loader(self) -> dict[str, Any]:
        # Compile the C source with clang if a .o does not already exist.
        obj = self.config.source_path.with_suffix(".o")
        if not obj.exists():
            clang = shutil.which("clang")
            if clang is None:
                raise EBPFLoadError("clang is required to compile the eBPF source")
            cmd = [
                clang,
                "-O2",
                "-target", "bpf",
                "-c", str(self.config.source_path),
                "-o", str(obj),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                raise EBPFLoadError(f"clang failed: {proc.stderr}")

        cmd = [
            "xdp-loader",
            "load",
            "-m", self.config.mode,
            self.config.interface,
            str(obj),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise EBPFLoadError(f"xdp-loader load failed: {proc.stderr}")

        return {
            "loaded": True,
            "mode": "xdp-loader",
            "interface": self.config.interface,
            "object": str(obj),
            "capture_ports": list(CAPTURE_PORTS),
            "source": str(self.config.source_path),
        }

    def _load_with_bcc(self) -> dict[str, Any]:
        import bcc  # type: ignore

        try:
            bpf = bcc.BPF(src_file=str(self.config.source_path))
        except Exception as exc:  # noqa: BLE001 - bcc raises a wide hierarchy
            raise EBPFLoadError(f"bcc.BPF failed: {exc}") from exc

        fn = getattr(bpf, "xdp_capture", None) or getattr(bpf, "xdp_prog", None)
        if fn is None:
            raise EBPFLoadError(
                "bcc loaded the source but could not find an XDP function "
                "(expected 'xdp_capture' or 'xdp_prog')"
            )

        try:
            ifname = self.config.interface.encode("utf-8")
            fn.attach_xdp(ifname)
        except Exception as exc:  # noqa: BLE001
            raise EBPFLoadError(f"attach_xdp failed: {exc}") from exc

        return {
            "loaded": True,
            "mode": "bcc",
            "interface": self.config.interface,
            "capture_ports": list(CAPTURE_PORTS),
            "source": str(self.config.source_path),
        }

    def _simulate(self) -> dict[str, Any]:
        return {
            "loaded": False,
            "mode": "simulation",
            "interface": self.config.interface,
            "capture_ports": list(CAPTURE_PORTS),
            "source": str(self.config.source_path),
            "note": (
                "xdp-loader and bcc are not available; the eBPF capture is "
                "simulated. See docs/LIMITATIONS.md for the reproduction tiers."
            ),
        }

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "interface": self.config.interface,
            "mode": self.config.mode,
            "source_path": str(self.config.source_path),
            "source_exists": self.config.source_path.exists(),
            "xdp_loader_available": shutil.which("xdp-loader") is not None,
            "bcc_available": self._bcc_available(),
            "clang_available": shutil.which("clang") is not None,
            "capture_ports": list(CAPTURE_PORTS),
            "is_root": os.geteuid() == 0 if hasattr(os, "geteuid") else False,
        }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the eBPF loader."""
    import json
    loader = EBPFLoader()
    try:
        result = loader.load()
    except (EBPFSourceMissing, EBPFLoadError) as exc:
        print(json.dumps({"status": "error", "error": str(exc), **loader.metadata()}, indent=2))
        return 1
    print(json.dumps({"status": "ok", **result, **loader.metadata()}, indent=2))
    return 0
