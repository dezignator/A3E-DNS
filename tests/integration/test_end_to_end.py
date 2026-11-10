"""End-to-end integration test for the A3E-DNS artifact.

Exercises the full Tier-A pipeline in toy mode:

    1. configuration loading and validation,
    2. the protocol adapters and the unified pipeline,
    3. the FL coordinator with a toy round,
    4. the anomaly detector on a synthetic window,
    5. the attack scenarios through the runner,
    6. the compliance checkers on the framework metadata,
    7. the verification targets.

The test asserts the verification targets from ``§6.16`` that are
reachable on a CPU-only run (the reported values, not the emulated
values). If any of these fail, the artifact is not reproducing the
thesis as expected.
"""

from __future__ import annotations

import pytest

from src.attacks.attack_runner import REPORTED_TABLE32, run_all
from src.compliance import run_all_checkers
from src.models.anomaly_detector import AnomalyDetector, DetectorConfig
from src.models.fl_coordinator import FLCoordinator, FLCoordinatorConfig
from src.protocols.base_adapter import PacketMetadata
from src.protocols.unified_pipeline import build_default_pipeline
from src.utils.config_loader import CONFIG_NAMES, load_config


# ---------------------------------------------------------------- configuration
def test_all_configs_load_and_validate():
    for name in CONFIG_NAMES:
        cfg = load_config(name)
        assert isinstance(cfg, dict)
        assert name in cfg


def test_qhe_config_matches_thesis_section_6_5():
    """§6.5 says n=256, q=4096. The config must match §6.5 (the Table 27
    command line is reproduced separately in ``table_27_commands.py``
    and is flagged as inconsistent in ``docs/LIMITATIONS.md`` §8)."""
    cfg = load_config("qhe")["qhe"]
    assert cfg["n"] == 256
    assert cfg["q"] == 4096


def test_fl_config_matches_thesis_section_6_6():
    cfg = load_config("federated_learning")["federated_learning"]
    assert cfg["transformer"]["layers"] == 8
    assert cfg["transformer"]["heads"] == 12
    assert cfg["transformer"]["attention_window"] == 512
    assert cfg["dp_sgd"]["epsilon"] == 0.68


# ---------------------------------------------------------------- pipeline
def test_pipeline_toy_end_to_end():
    packets = [
        PacketMetadata(
            timestamp=1762732800.0 + i,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=50000,
            dst_port=443,
            transport="tcp",
            payload_length=512,
            http2_frame_type=1,
            tls_version="TLSv1.3",
            alpn=["h2"],
        )
        for i in range(5)
    ]
    pipeline = build_default_pipeline()
    results = pipeline.run(packets)
    assert len(results) == 5


# ---------------------------------------------------------------- FL
def test_fl_coordinator_toy_round():
    import numpy as np
    coord = FLCoordinator(FLCoordinatorConfig(rounds=1, clients=5), model_dim=8)
    rng = np.random.default_rng(20261130)
    updates = [rng.normal(0.0, 0.1, size=8) for _ in range(5)]
    result = coord.run_round(updates, round_index=0)
    assert result.round == 0
    assert result.n_updates_received == 5
    assert result.n_updates_used >= 1


# ---------------------------------------------------------------- detector
def test_anomaly_detector_toy_window():
    import numpy as np
    cfg = DetectorConfig(backend="numpy")
    detector = AnomalyDetector(cfg)
    rng = np.random.default_rng(20261130)
    window = rng.normal(0.0, 1.0, size=(cfg.attention_window, cfg.input_dim))
    result = detector.score(window)
    assert 0.0 <= result.score <= 1.0
    assert result.threshold >= 0.0


# ---------------------------------------------------------------- attacks
def test_attack_runner_matches_table32():
    results = {r.scenario_id: r for r in run_all()}
    assert len(results) == 5
    for sid in ("S1", "S2", "S3", "S4", "S5"):
        assert results[sid].reported_success_rate == pytest.approx(
            REPORTED_TABLE32[sid]["success"]
        )
        assert results[sid].reported_fnr == pytest.approx(
            REPORTED_TABLE32[sid]["fnr"]
        )


# ---------------------------------------------------------------- compliance
def test_compliance_checkers_full_metadata():
    metadata = {}
    for name in CONFIG_NAMES:
        metadata[name] = load_config(name)[name]
    results = run_all_checkers(metadata)
    assert len(results) == 5
    for r in results:
        assert r.verdict.value in {"pass", "partial", "fail", "not_applicable"}


# ---------------------------------------------------------------- §6.16 targets
@pytest.mark.parametrize(
    "field,expected",
    [
        ("detection_accuracy", 99.94),
        ("false_positive_rate", 0.17),
        ("p99_latency_ms", 1.42),
        ("throughput_m_qps", 22.5),
        ("adversarial_robustness", 96.5),
        ("privacy_epsilon", 0.68),
    ],
)
def test_table33_proposed_targets(field, expected):
    """Every proposed value in Table 33 must match the reported target."""
    from src.hardware_simulation.perf_model import TABLE33_PROPOSED
    assert TABLE33_PROPOSED[field] == pytest.approx(expected)
