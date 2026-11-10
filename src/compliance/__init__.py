"""Compliance and certification checkers — thesis §6.9, Table 29.

Implements the five technical-property checkers for the standards listed
in Table 29:

    * NIST CSF       — Identify / Protect / Detect / Respond / Recover
    * GDPR           — data minimisation + DP bound + ZK attestation
    * ISO 27001      — access control + audit trail
    * PCI DSS        — cardholder isolation via AMPS
    * FISMA          — crypto protection + hardware entropy + FL isolation

**Important.** These are *technical properties*, not compliance
certifications. A full compliance determination requires an
organisational audit (record keeping, retention, access control, breach
notification, governance) which is out of scope for this artifact.
This caveat is stated verbatim in Table 29 of the thesis and repeated
in every checker's ``metadata()`` output.

All five checkers share the same interface:

    Checker(metadata: dict) -> CheckResult
    .verdict           -> "pass" | "partial" | "fail" | "not_applicable"
    .properties        -> tuple[str, ...]  # the technical properties
    .to_dict()         -> dict

They are deliberately lightweight: they check that the framework's
metadata (config files, run manifest) contains the fields each
standard's technical property depends on, and record a verdict. They
are not legal advice and do not claim to certify anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "ComplianceVerdict",
    "ComplianceResult",
    "ComplianceChecker",
    "NISTCSFChecker",
    "GDPRChecker",
    "ISO27001Checker",
    "PCIDSSChecker",
    "FISMAChecker",
    "ALL_CHECKERS",
    "run_all_checkers",
]


# --------------------------------------------------------------- verdict
class ComplianceVerdict(str, Enum):
    """Verdict returned by a compliance checker."""

    PASS = "pass"
    PARTIAL = "partial"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"


# --------------------------------------------------------------- result
@dataclass(frozen=True)
class ComplianceResult:
    """Result of a single compliance check."""

    standard: str
    verdict: ComplianceVerdict
    properties: tuple[str, ...]
    limitations: tuple[str, ...] = field(default_factory=tuple)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard": self.standard,
            "verdict": self.verdict.value,
            "properties": list(self.properties),
            "limitations": list(self.limitations),
            "details": self.details,
        }


# --------------------------------------------------------------- base
class ComplianceChecker:
    """Base class for compliance checkers.

    Subclasses must define:

    * ``standard``           — the standard name (matches Table 29)
    * ``properties``         — the technical properties provided
    * ``limitations``        — the limits documented in Table 29
    * ``check(metadata)``    — the verdict logic

    The base ``__call__`` runs ``check`` and packages the result.
    """

    standard: str = ""
    properties: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    def __call__(self, metadata: dict[str, Any]) -> ComplianceResult:
        verdict, details = self.check(metadata)
        return ComplianceResult(
            standard=self.standard,
            verdict=verdict,
            properties=self.properties,
            limitations=self.limitations,
            details=details,
        )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        raise NotImplementedError


# --------------------------------------------------------------- NIST CSF
class NISTCSFChecker(ComplianceChecker):
    """NIST Cybersecurity Framework technical-property checker."""

    standard = "NIST CSF"
    properties = (
        "Identify: framework inventory is present in the manifest",
        "Protect: AEE + QHE + FL isolation fields are configured",
        "Detect: threat-intel correlation is enabled",
        "Respond: AMPS sandbox is configured",
        "Recover: failover paths are configured for all components",
    )
    limitations = (
        "No continuous-monitoring certification",
        "Organisational audit required for full NIST CSF compliance",
    )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        found = {
            "identify": "manifest" in metadata or "components" in metadata,
            "protect": all(k in metadata for k in ("aee", "qhe", "federated_learning")),
            "detect": "threat_intel" in metadata,
            "respond": "amps" in metadata,
            "recover": "failover" in metadata or "failover_config" in metadata,
        }
        n_ok = sum(1 for v in found.values() if v)
        verdict = ComplianceVerdict.PASS if n_ok == 5 else (
            ComplianceVerdict.PARTIAL if n_ok >= 3 else ComplianceVerdict.FAIL
        )
        return verdict, {"found": found, "n_ok": n_ok, "n_total": 5}


# --------------------------------------------------------------- GDPR
class GDPRChecker(ComplianceChecker):
    """GDPR technical-property checker."""

    standard = "GDPR"
    properties = (
        "Data minimisation: FL keeps raw queries on the client",
        "Differential privacy: ε bound is set (ε = 0.68)",
        "ZK attestation: resolver integrity without metadata disclosure",
        "Storage limitation: threat feeds have bounded retention",
    )
    limitations = (
        "Requires organisational audit",
        "Does not certify GDPR compliance",
    )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        fl = metadata.get("federated_learning", {})
        dp = fl.get("dp_sgd", {}) if isinstance(fl, dict) else {}
        ti = metadata.get("threat_intel", {})
        found = {
            "data_minimisation": bool(fl),
            "differential_privacy": bool(dp.get("enabled")),
            "epsilon_bound": "epsilon" in dp,
            "zk_attestation": bool(metadata.get("zk") or metadata.get("zk_attestation")),
            "storage_limitation": bool(ti),
        }
        n_ok = sum(1 for v in found.values() if v)
        verdict = ComplianceVerdict.PASS if n_ok == 5 else (
            ComplianceVerdict.PARTIAL if n_ok >= 3 else ComplianceVerdict.FAIL
        )
        return verdict, {"found": found, "n_ok": n_ok, "n_total": 5}


# --------------------------------------------------------------- ISO 27001
class ISO27001Checker(ComplianceChecker):
    """ISO 27001 technical-property checker."""

    standard = "ISO 27001"
    properties = (
        "Access control at the FL coordinator",
        "Audit trail via internal-log correlation",
        "Role separation: coordinator / QHE / anomaly / data plane",
    )
    limitations = (
        "Not a certified ISMS",
        "Organisational audit required",
    )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        fl = metadata.get("federated_learning", {})
        agg = fl.get("aggregation", {}) if isinstance(fl, dict) else {}
        ti = metadata.get("threat_intel", {})
        ilogs = ti.get("internal_logs", {}) if isinstance(ti, dict) else {}
        found = {
            "fl_access_control": bool(agg),
            "audit_trail": bool(ilogs.get("enabled")),
            "role_separation": "roles" in metadata or "testbed" in metadata,
        }
        n_ok = sum(1 for v in found.values() if v)
        verdict = ComplianceVerdict.PASS if n_ok == 3 else (
            ComplianceVerdict.PARTIAL if n_ok >= 2 else ComplianceVerdict.FAIL
        )
        return verdict, {"found": found, "n_ok": n_ok, "n_total": 3}


# --------------------------------------------------------------- PCI DSS
class PCIDSSChecker(ComplianceChecker):
    """PCI DSS technical-property checker."""

    standard = "PCI DSS"
    properties = (
        "Cardholder-data isolation via the AMPS sandbox",
        "No plaintext exposure of query payloads",
        "Authenticated transport (TLS 1.3 / QUIC)",
    )
    limitations = (
        "Scope limited to encrypted DNS traffic",
        "Organisational audit required",
    )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        amps = metadata.get("amps", {})
        qhe = metadata.get("qhe", {})
        found = {
            "sandbox_isolation": bool(amps),
            "no_plaintext_payload": bool(qhe),  # QHE computes on ciphertext only
            "authenticated_transport": "protocols" in metadata or "testbed" in metadata,
        }
        n_ok = sum(1 for v in found.values() if v)
        verdict = ComplianceVerdict.PASS if n_ok == 3 else (
            ComplianceVerdict.PARTIAL if n_ok >= 2 else ComplianceVerdict.FAIL
        )
        return verdict, {"found": found, "n_ok": n_ok, "n_total": 3}


# --------------------------------------------------------------- FISMA
class FISMAChecker(ComplianceChecker):
    """FISMA technical-property checker."""

    standard = "FISMA"
    properties = (
        "Cryptographic protection of data-in-use via QHE",
        "Hardware entropy (RDRAND / RDSEED) available",
        "FL isolation from the central aggregator",
    )
    limitations = (
        "Post-quantum assumption is conjectural",
        "Organisational audit required",
    )

    def check(self, metadata: dict[str, Any]) -> tuple[ComplianceVerdict, dict[str, Any]]:
        qhe = metadata.get("qhe", {})
        aee = metadata.get("aee", {})
        fl = metadata.get("federated_learning", {})
        entropy = aee.get("entropy_source") if isinstance(aee, dict) else None
        found = {
            "qhe_configured": bool(qhe),
            "hardware_entropy": bool(entropy),
            "fl_isolation": bool(fl.get("aggregation")) if isinstance(fl, dict) else False,
        }
        n_ok = sum(1 for v in found.values() if v)
        verdict = ComplianceVerdict.PASS if n_ok == 3 else (
            ComplianceVerdict.PARTIAL if n_ok >= 2 else ComplianceVerdict.FAIL
        )
        return verdict, {"found": found, "n_ok": n_ok, "n_total": 3}


# --------------------------------------------------------------- catalogue
ALL_CHECKERS: tuple[ComplianceChecker, ...] = (
    NISTCSFChecker(),
    GDPRChecker(),
    ISO27001Checker(),
    PCIDSSChecker(),
    FISMAChecker(),
)


def run_all_checkers(metadata: dict[str, Any]) -> list[ComplianceResult]:
    """Run all five checkers on the given metadata and return their results."""
    return [checker(metadata) for checker in ALL_CHECKERS]
