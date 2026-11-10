"""Programmable data plane for the A3E-DNS artifact (Chapter 6).

The data plane is a **3-stage P4 pipeline** (§6.12) plus an **eBPF /
XDP** packet-capture path (§6.11.2):

    p4_telemetry          — driver that builds and loads the 3-stage P4 pipeline
    p4_pipeline/          — the P4 source files
        parser.p4             Stage 1: protocol identification
        match_action.p4       Stage 2: statistics
        metadata_gen.p4       Stage 3: telemetry
    ebpf_capture.c        — XDP filter (source)
    ebpf_loader.py        — loads the XDP program via the bpf() syscall
    mininet_topology.py   — BMv2 + Mininet topology

The P4 pipeline is **evaluated on BMv2 + Mininet + P4Runtime** (§6.12).
It is not benchmarked against software-based monitoring on the same
hardware; that comparison is out of scope and is identified as future
work in ``docs/LIMITATIONS.md``.

The contribution of this subpackage is the **specific 3-stage packet
processing pipeline** designed for encrypted-DNS metadata extraction,
not the P4 / BMv2 / Mininet frameworks (which are published).
"""

from __future__ import annotations

__all__ = [
    "p4_telemetry",
    "ebpf_loader",
    "mininet_topology",
]
