"""Integration tests for the S1–S5 attack simulators.

Covers the orchestration in ``src.attacks.attack_runner`` and the
per-scenario simulators in ``src.attacks``. Each scenario is exercised
through the runner, and the reported Table 32 values are checked
against the ``REPORTED_TABLE32`` reference.

These are CPU-only tests. They do not invoke ``tshark``, ``dnscat2``,
``openssl``, or ``ART`` unless those tools are installed; in that case
the simulators still return their deterministic simulated results.
"""

from __future__ import annotations

import pytest

from src.attacks.attack_runner import (
    REPORTED_TABLE32,
    AttackRunner,
    ScenarioResult,
    run_all,
    run_scenario,
)


# ---------------------------------------------------------------- runner order
def test_runner_order_is_s1_to_s5():
    assert AttackRunner.ORDER == ("S1", "S2", "S3", "S4", "S5")


def test_runner_run_all_returns_five():
    runner = AttackRunner()
    results = runner.run_all()
    assert len(results) == 5
    assert [r.scenario_id for r in results] == ["S1", "S2", "S3", "S4", "S5"]


def test_runner_unknown_scenario_raises():
    runner = AttackRunner()
    with pytest.raises(KeyError):
        runner.run_scenario("S6")


# ---------------------------------------------------------------- Table 32 values
def test_reported_table32_has_all_scenarios():
    assert set(REPORTED_TABLE32) == {"S1", "S2", "S3", "S4", "S5"}


def test_reported_table32_s1_values():
    assert REPORTED_TABLE32["S1"]["success"] == pytest.approx(98.7)
    assert REPORTED_TABLE32["S1"]["fnr"] == pytest.approx(1.3)
    assert REPORTED_TABLE32["S1"]["response_ms"] == pytest.approx(0.4)


def test_reported_table32_s2_values():
    assert REPORTED_TABLE32["S2"]["success"] == pytest.approx(99.2)
    assert REPORTED_TABLE32["S2"]["fnr"] == pytest.approx(0.8)


def test_reported_table32_s3_values():
    assert REPORTED_TABLE32["S3"]["success"] == pytest.approx(96.5)
    assert REPORTED_TABLE32["S3"]["fnr"] == pytest.approx(3.5)


def test_reported_table32_s4_values():
    assert REPORTED_TABLE32["S4"]["success"] == pytest.approx(100.0)
    assert REPORTED_TABLE32["S4"]["fnr"] == pytest.approx(0.0)


def test_reported_table32_s5_values():
    assert REPORTED_TABLE32["S5"]["success"] == pytest.approx(97.8)
    assert REPORTED_TABLE32["S5"]["fnr"] == pytest.approx(2.2)


# ---------------------------------------------------------------- per-scenario detection
def test_s1_detected():
    runner = AttackRunner()
    r = runner.run_scenario("S1")
    assert isinstance(r, ScenarioResult)
    assert r.scenario_id == "S1"
    assert r.name == "S1-Timing"
    assert r.detected is True
    assert "tshark" in r.command.lower()


def test_s2_detected():
    runner = AttackRunner()
    r = runner.run_scenario("S2")
    assert r.scenario_id == "S2"
    assert r.name == "S2-Tunnel"
    assert r.detected is True
    assert "dnscat2" in r.command.lower()


def test_s3_detected():
    runner = AttackRunner()
    r = runner.run_scenario("S3")
    assert r.scenario_id == "S3"
    assert r.name == "S3-Poison"
    assert r.detected is True
    assert "poison" in r.command.lower()


def test_s4_detected():
    runner = AttackRunner()
    r = runner.run_scenario("S4")
    assert r.scenario_id == "S4"
    assert r.name == "S4-Quantum"
    assert r.detected is True
    assert "kyber1024" in r.command.lower()


def test_s5_detected():
    runner = AttackRunner()
    r = runner.run_scenario("S5")
    assert r.scenario_id == "S5"
    assert r.name == "S5-Evasion"
    assert r.detected is True
    assert "craft_queries" in r.command.lower()


# ---------------------------------------------------------------- determinism
def test_run_scenario_deterministic():
    """Running the same scenario twice produces the same result (same
    reported values, same detection decision)."""
    a = run_scenario("S1")
    b = run_scenario("S1")
    assert a.detected == b.detected
    assert a.reported_success_rate == b.reported_success_rate
    assert a.reported_fnr == b.reported_fnr


def test_run_all_deterministic():
    a = run_all()
    b = run_all()
    for ra, rb in zip(a, b):
        assert ra.detected == rb.detected
        assert ra.reported_success_rate == rb.reported_success_rate


# ---------------------------------------------------------------- result dict
def test_scenario_result_to_dict():
    r = run_scenario("S1")
    d = r.to_dict()
    for key in ("scenario_id", "name", "command", "detected",
                "reported_success_rate", "reported_fnr",
                "reported_response_ms", "metrics"):
        assert key in d
