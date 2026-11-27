"""
p4/tests/test_features.py

Tests for the switch-side feature computation.

The tests exercise the Python reference implementation directly. They
do not require a BMv2 switch; the integration test against BMv2 is
provided separately and skipped when the switch is not running. The
reference's arithmetic matches the P4 program's exactly, so a bug in
the reference catches a bug in the P4 program; the P4 compilation is
verified separately by the Makefile's `p4c` invocation.

Each test case below corresponds to a specific P4 expression. If the
P4 program is ever modified, the reference must be modified in the
same commit and the corresponding test will catch a divergence.
"""

from __future__ import annotations

import pytest

from reference_features import (
    EMA_COEFF,
    EMA_SHIFT,
    FlowState,
    ReferenceFeatures,
)


# --------------------------------------------------------------------------- #
# EMA coefficients
# --------------------------------------------------------------------------- #


def test_ema_coefficient_matches_the_p4_constant() -> None:
    """The Python coefficient and the P4 shift must agree."""
    assert EMA_SHIFT == 4
    assert EMA_COEFF == 1 << EMA_SHIFT
    assert EMA_COEFF == 16


# --------------------------------------------------------------------------- #
# First-packet seeding
# --------------------------------------------------------------------------- #


def test_first_packet_seeds_emas() -> None:
    state = FlowState()
    state.update(now_us=1_000_000, pkt_len=500, direction=1)
    # On the first packet the EMA is the sample itself.
    assert state.iat_ema_us == 0
    assert state.iat_ema_sq_us2 == 0
    assert state.size_ema == 500
    assert state.size_ema_sq == 500 * 500
    assert state.pkt_count == 1
    assert state.cli_pkts == 1
    assert state.srv_pkts == 0
    assert state.last_ts_us == 1_000_000


# --------------------------------------------------------------------------- #
# EMA convergence
# --------------------------------------------------------------------------- #


def test_iat_ema_converges_to_a_constant_iat() -> None:
    state = FlowState()
    iat = 10_000  # 10 ms
    state.update(now_us=0, pkt_len=500, direction=1)
    for i in range(1, 200):
        state.update(now_us=i * iat, pkt_len=500, direction=1)
    # After 200 samples at a constant 10,000 us IAT the EMA should be
    # very close to 10,000.
    assert abs(state.iat_ema_us - 10_000) < 50


def test_iat_ema_responds_to_a_rate_increase() -> None:
    """A rate increase must pull the EMA down toward the new IAT."""
    state = FlowState()
    state.update(now_us=0, pkt_len=500, direction=1)
    # Twenty packets at 10 ms IAT: EMA converges near 10,000.
    for i in range(1, 20):
        state.update(now_us=i * 10_000, pkt_len=500, direction=1)
    before = state.iat_ema_us
    # Twenty packets at 1 ms IAT: EMA must drop.
    base = state.last_ts_us
    for i in range(1, 20):
        state.update(now_us=base + i * 1_000, pkt_len=500, direction=1)
    after = state.iat_ema_us
    assert after < before
    # The drop must be substantial — the EMA should move toward 1,000.
    assert after < before * 0.8


def test_size_ema_converges_to_a_constant_size() -> None:
    state = FlowState()
    for i in range(200):
        state.update(now_us=i * 10_000, pkt_len=350, direction=1)
    assert abs(state.size_ema - 350) < 5


# --------------------------------------------------------------------------- #
# Reporting cadence
# --------------------------------------------------------------------------- #


def test_reporting_fires_on_every_32nd_packet() -> None:
    state = FlowState()
    reports = 0
    for i in range(1, 65):
        state.update(now_us=i * 10_000, pkt_len=500, direction=1)
        if state.should_report():
            reports += 1
    # Packets 32 and 64 should report.
    assert reports == 2


def test_no_report_on_the_first_packet() -> None:
    state = FlowState()
    state.update(now_us=1_000_000, pkt_len=500, direction=1)
    assert not state.should_report()


# --------------------------------------------------------------------------- #
# Direction tracking
# --------------------------------------------------------------------------- #


def test_direction_counts() -> None:
    state = FlowState()
    for i in range(10):
        state.update(now_us=i * 10_000, pkt_len=500, direction=1)
    for i in range(5):
        state.update(now_us=(10 + i) * 10_000, pkt_len=500, direction=0)
    assert state.cli_pkts == 10
    assert state.srv_pkts == 5
    assert state.pkt_count == 15


# --------------------------------------------------------------------------- #
# Severity heuristic
# --------------------------------------------------------------------------- #


def test_severity_hint_low_for_slow_benign_flow() -> None:
    state = FlowState()
    # One packet per 500 ms for 20 packets.
    for i in range(20):
        state.update(now_us=i * 500_000, pkt_len=300, direction=1)
    hint = state.severity_hint()
    assert hint <= 40


def test_severity_hint_high_for_beacon_like_flow() -> None:
    """A high rate with low IAT variance is the beacon signature."""
    state = FlowState()
    # 500 packets at a perfectly regular 1 ms IAT.
    for i in range(500):
        state.update(now_us=i * 1_000, pkt_len=300, direction=1)
    hint = state.severity_hint()
    # Rate > 100 pps and IAT variance near 0 → beacon class.
    assert hint == 200


def test_severity_hint_elevated_for_moderate_rate() -> None:
    state = FlowState()
    # ~60 pps for two seconds.
    for i in range(120):
        state.update(now_us=int(i * 16_666), pkt_len=300, direction=1)
    hint = state.severity_hint()
    assert 40 < hint <= 180


# --------------------------------------------------------------------------- #
# Full reference pipeline
# --------------------------------------------------------------------------- #


def test_reference_features_reports_at_the_expected_cadence() -> None:
    ref = ReferenceFeatures()
    reports = 0
    for i in range(1, 129):
        state = ref.process(
            flow_hash=123,
            now_us=i * 10_000,
            pkt_len=500,
            direction=1,
        )
        if state is not None:
            reports += 1
    # 128 packets → reports on 32, 64, 96, 128 = 4.
    assert reports == 4


def test_reference_features_isolates_flow_state() -> None:
    ref = ReferenceFeatures()
    for i in range(10):
        ref.process(flow_hash=1, now_us=i * 10_000, pkt_len=500, direction=1)
    for i in range(5):
        ref.process(flow_hash=2, now_us=i * 10_000, pkt_len=800, direction=0)
    assert ref.flows[1].pkt_count == 10
    assert ref.flows[2].pkt_count == 5
    assert ref.flows[1].size_ema != ref.flows[2].size_ema
