"""Unit tests for :mod:`src.compliance`.

Covers the five Table-29 checkers:

    * NIST CSF
    * GDPR
    * ISO 27001
    * PCI DSS
    * FISMA

**Important:** the checkers return a ``verdict`` based on the presence
of specific configuration fields. They do **not** certify compliance;
see ``docs/SECURITY_ARGUMENTS.md`` §7 and the Table 29 warning.
"""

from __future__ import annotations

import pytest

from src.compliance import (
    ALL_CHECKERS,
    ComplianceChecker,
    ComplianceResult,
    ComplianceVerdict,
    FISMAChecker,
    GDPRChecker,
    ISO27001Checker,
    NISTCSFChecker,
    PCIDSSChecker,
    run_all_checkers,
)


# ---------------------------------------------------------------- minimal metadata
@pytest.fixture
def full_metadata() -> dict:
    """Metadata that satisfies every checker."""
    return {
        "manifest": {},
        "components": {},
        "aee": {"se3_dim": 1, "key_bits": 256, "entropy_source": ["/dev/urandom"]},
        "qhe": {"scheme": "ring_lwe", "n": 256, "q": 4096},
        "federated_learning": {
            "dp_sgd": {"enabled": True, "epsilon": 0.68},
            "aggregation": {"method": "geometric_median"},
            "performance": {"rounds": 100, "clients": 100},
        },
        "threat_intel": {
            "internal_logs": {"enabled": True},
            "cert_alerts": {"enabled": True},
        },
        "amps": {
            "control": {},
            "divergence": {"metrics": ["kl"]},
            "isolation": {"doh": {}, "dot": {}, "doq": {}},
            "resources": {"memory_gb": 2, "timeout_seconds": 30},
            "performance": {"p99_mitigation_ms": 1.5},
        },
        "failover": {},
        "zk_attestation": {},
        "roles": {},
    }


# ---------------------------------------------------------------- base
def test_compliance_result_to_dict():
    r = ComplianceResult(
        standard="TEST",
        verdict=ComplianceVerdict.PASS,
        properties=("p1", "p2"),
        limitations=("l1",),
        details={"key": "value"},
    )
    d = r.to_dict()
    assert d["standard"] == "TEST"
    assert d["verdict"] == "pass"
    assert d["properties"] == ["p1", "p2"]
    assert d["limitations"] == ["l1"]
    assert d["details"] == {"key": "value"}


def test_compliance_verdict_enum():
    assert ComplianceVerdict.PASS.value == "pass"
    assert ComplianceVerdict.PARTIAL.value == "partial"
    assert ComplianceVerdict.FAIL.value == "fail"
    assert ComplianceVerdict.NOT_APPLICABLE.value == "not_applicable"


def test_all_checkers_count():
    assert len(ALL_CHECKERS) == 5


def test_all_checkers_have_standard_name():
    for checker in ALL_CHECKERS:
        assert checker.standard
        assert isinstance(checker.standard, str)


# ---------------------------------------------------------------- NIST CSF
def test_nistcsf_pass(full_metadata):
    r = NISTCSFChecker()(full_metadata)
    assert r.standard == "NIST CSF"
    assert r.verdict == ComplianceVerdict.PASS
    assert len(r.properties) == 5


def test_nistcsf_partial_when_missing():
    r = NISTCSFChecker()({})
    assert r.verdict == ComplianceVerdict.FAIL


# ---------------------------------------------------------------- GDPR
def test_gdpr_pass(full_metadata):
    r = GDPRChecker()(full_metadata)
    assert r.standard == "GDPR"
    assert r.verdict == ComplianceVerdict.PASS


def test_gdpr_fail_when_fl_missing():
    r = GDPRChecker()({})
    assert r.verdict == ComplianceVerdict.FAIL


# ---------------------------------------------------------------- ISO 27001
def test_iso27001_pass(full_metadata):
    r = ISO27001Checker()(full_metadata)
    assert r.standard == "ISO 27001"
    assert r.verdict == ComplianceVerdict.PASS


def test_iso27001_partial_when_audit_missing():
    metadata = {
        "federated_learning": {"aggregation": {"method": "geometric_median"}},
        # no internal_logs, no roles
    }
    r = ISO27001Checker()(metadata)
    assert r.verdict == ComplianceVerdict.PARTIAL


# ---------------------------------------------------------------- PCI DSS
def test_pcidss_pass(full_metadata):
    r = PCIDSSChecker()(full_metadata)
    assert r.standard == "PCI DSS"
    assert r.verdict == ComplianceVerdict.PASS


def test_pcidss_partial_without_testbed():
    metadata = {"amps": {}, "qhe": {}}
    r = PCIDSSChecker()(metadata)
    assert r.verdict == ComplianceVerdict.PARTIAL


# ---------------------------------------------------------------- FISMA
def test_fisma_pass(full_metadata):
    r = FISMAChecker()(full_metadata)
    assert r.standard == "FISMA"
    assert r.verdict == ComplianceVerdict.PASS


def test_fisma_fail_without_entropy():
    metadata = {"qhe": {}, "federated_learning": {"aggregation": {}}}
    r = FISMAChecker()(metadata)
    assert r.verdict == ComplianceVerdict.FAIL


# ---------------------------------------------------------------- run_all
def test_run_all_checkers_returns_five_results(full_metadata):
    results = run_all_checkers(full_metadata)
    assert len(results) == 5
    standards = {r.standard for r in results}
    assert standards == {"NIST CSF", "GDPR", "ISO 27001", "PCI DSS", "FISMA"}


def test_run_all_checkers_all_pass_with_full_metadata(full_metadata):
    results = run_all_checkers(full_metadata)
    for r in results:
        assert r.verdict == ComplianceVerdict.PASS, f"{r.standard} not pass"
