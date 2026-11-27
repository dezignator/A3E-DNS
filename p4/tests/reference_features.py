"""
p4/tests/reference_features.py

Reference implementation of the switch's EMA feature computation in
Python.

We wrote this implementation so that the P4 program's register arithmetic
can be verified without a running BMv2 switch. The reference takes the
same per-packet inputs the switch sees (timestamp, length, direction)
and produces the same register state the switch would produce. The
pytest module below tests the reference against known cases; a separate
integration test (marked as requiring BMv2) validates the P4 program
against the reference.

The EMA coefficient is the same 1/16 the P4 program uses. The integer
truncation matches P4's `>>` operator, which is a logical right shift
on unsigned integers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


EMA_SHIFT = 4
EMA_COEFF = 1 << EMA_SHIFT  # 16


@dataclass
class FlowState:
    """The register state for a single flow."""

    last_ts_us: int = 0
    iat_ema_us: int = 0
    iat_ema_sq_us2: int = 0
    size_ema: int = 0
    size_ema_sq: int = 0
    pkt_count: int = 0
    cli_pkts: int = 0
    srv_pkts: int = 0

    def update(
        self,
        now_us: int,
        pkt_len: int,
        direction: int,
    ) -> None:
        iat = 0 if self.last_ts_us == 0 else (now_us - self.last_ts_us) & 0xFFFFFFFF

        if self.last_ts_us == 0:
            self.iat_ema_us = iat
            self.iat_ema_sq_us2 = (iat * iat) & 0xFFFFFFFF
            self.size_ema = pkt_len
            self.size_ema_sq = (pkt_len * pkt_len) & 0xFFFFFFFF
        else:
            # The P4 expression is `ema + ((x - ema) >> shift)`; we
            # replicate it exactly, including the unsigned wrapping.
            self.iat_ema_us = (
                self.iat_ema_us
                + (((iat - self.iat_ema_us) & 0xFFFFFFFF) >> EMA_SHIFT)
            ) & 0xFFFFFFFF
            self.iat_ema_sq_us2 = (
                self.iat_ema_sq_us2
                + ((((iat * iat) & 0xFFFFFFFF) - self.iat_ema_sq_us2) & 0xFFFFFFFF) >> EMA_SHIFT
            ) & 0xFFFFFFFF
            self.size_ema = (
                self.size_ema
                + (((pkt_len - self.size_ema) & 0xFFFFFFFF) >> EMA_SHIFT)
            ) & 0xFFFFFFFF
            self.size_ema_sq = (
                self.size_ema_sq
                + ((((pkt_len * pkt_len) & 0xFFFFFFFF) - self.size_ema_sq) & 0xFFFFFFFF) >> EMA_SHIFT
            ) & 0xFFFFFFFF

        self.last_ts_us = now_us
        self.pkt_count = (self.pkt_count + 1) & 0xFFFF
        if direction == 1:
            self.cli_pkts = (self.cli_pkts + 1) & 0xFFFF
        else:
            self.srv_pkts = (self.srv_pkts + 1) & 0xFFFF

    def should_report(self) -> bool:
        return (self.pkt_count & 0x1F) == 0

    def severity_hint(self) -> int:
        # Rate is computed over the elapsed time since the flow's first
        # packet; we approximate it with pkt_count over 1 second when
        # the flow has lasted that long, else pkt_count.
        elapsed = max(1, self.last_ts_us)
        rate = min(255, self.pkt_count * 1_000_000 // elapsed)
        iat_var = max(0, self.iat_ema_sq_us2 - self.iat_ema_us * self.iat_ema_us)
        if rate > 100 and iat_var < 100:
            return 200
        if rate > 100:
            return 180
        if rate > 50:
            return 120
        return 40


class ReferenceFeatures:
    """The full reference feature pipeline."""

    def __init__(self) -> None:
        self.flows: dict[int, FlowState] = {}

    def process(
        self,
        flow_hash: int,
        now_us: int,
        pkt_len: int,
        direction: int,
    ) -> Optional[FlowState]:
        state = self.flows.setdefault(flow_hash, FlowState())
        state.update(now_us, pkt_len, direction)
        if state.should_report():
            return state
        return None
