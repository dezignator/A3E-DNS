"""Attack orchestrator. Thesis Table 32 (S1–S5) and Table 31 (6 phases).

The runner executes all five scenarios of Table 32 in a fixed order
(S1 → S2 → S3 → S4 → S5) and aggregates their results into a single
report that mirrors the Table 32 columns:

    ID | Tool | Command | Traffic Pattern | Threshold | Response | Success | FNR

Each per-scenario result is produced by the corresponding module in
``src.attacks``. Results are deterministic given the per-scenario
configurations; the runner does not introduce additional randomness.

The runner also produces a summary row that the verification script
compares against ``expected_outputs/table_32_expected.json``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from src.attacks import (
    s1_timing,
    s2_tunnel,
    s3_poison,
    s4_quantum,
    s5_evasion,
)

__all__ = [
    "AttackRunner",
    "ScenarioResult",
    "REPORTED_TABLE32",
    "run_all",
    "run_scenario",
]


# --------------------------------------------------------------- reported values
#: Reported values from Table 32 (Chapter 6). These are the values that the
#: verification script checks against; they are NOT computed by the runner.
REPORTED_TABLE32: dict[str, dict[str, float]] = {
    "S1": {"success": s1_timing.SUCCESS_RATE, "fnr": s1_timing.FNR, "response_ms": s1_timing.RESPONSE_MS},
    "S2": {"success": s2_tunnel.SUCCESS_RATE, "fnr": s2_tunnel.FNR, "response_ms": s2_tunnel.RESPONSE_MS},
    "S3": {"success": s3_poison.SUCCESS_RATE, "fnr": s3_poison.FNR, "response_ms": s3_poison.RESPONSE_MS},
    "S4": {"success": s4_quantum.SUCCESS_RATE, "fnr": s4_quantum.FNR, "response_ms": s4_quantum.RESPONSE_MS},
    "S5": {"success": s5_evasion.SUCCESS_RATE, "fnr": s5_evasion.FNR, "response_ms": s5_evasion.RESPONSE_MS},
}


# --------------------------------------------------------------- result
@dataclass
class ScenarioResult:
    """Result of one scenario as returned by the runner."""

    scenario_id: str
    name: str
    command: str
    detected: bool
    reported_success_rate: float
    reported_fnr: float
    reported_response_ms: float
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# --------------------------------------------------------------- runner
class AttackRunner:
    """Orchestrates the S1–S5 scenarios."""

    #: Fixed execution order (Table 32).
    ORDER: tuple[str, ...] = ("S1", "S2", "S3", "S4", "S5")

    def __init__(self, *, configs: dict[str, Any] | None = None) -> None:
        self.configs = configs or {}

    # --------------------------------------------------------------- API
    def run_scenario(self, scenario_id: str) -> ScenarioResult:
        """Run a single scenario by id (``"S1"`` … ``"S5"``)."""
        if scenario_id not in self.ORDER:
            raise KeyError(
                f"unknown scenario {scenario_id!r}; expected one of {self.ORDER}"
            )
        cfg = self.configs.get(scenario_id)
        if scenario_id == "S1":
            result = s1_timing.evaluate(cfg)
            return ScenarioResult(
                scenario_id="S1",
                name="S1-Timing",
                command=str(s1_timing.build_tshark_command()),
                detected=result.detected,
                reported_success_rate=result.reported_success_rate,
                reported_fnr=result.reported_fnr,
                reported_response_ms=result.reported_response_ms,
                metrics={"kl_divergence": result.kl_divergence, "threshold": result.threshold},
            )
        if scenario_id == "S2":
            result = s2_tunnel.evaluate(cfg)
            return ScenarioResult(
                scenario_id="S2",
                name="S2-Tunnel",
                command=str(s2_tunnel.build_dnscat2_command()),
                detected=result.detected,
                reported_success_rate=result.reported_success_rate,
                reported_fnr=result.reported_fnr,
                reported_response_ms=result.reported_response_ms,
                metrics={"entropy_bits": result.entropy_bits, "threshold_bits": result.threshold_bits},
            )
        if scenario_id == "S3":
            result = s3_poison.evaluate(cfg)
            return ScenarioResult(
                scenario_id="S3",
                name="S3-Poison",
                command=s3_poison.build_command(),
                detected=result.detected,
                reported_success_rate=result.reported_success_rate,
                reported_fnr=result.reported_fnr,
                reported_response_ms=result.reported_response_ms,
                metrics={
                    "n_malicious_detected": result.n_malicious_detected,
                    "n_malicious_total": result.n_malicious_total,
                },
            )
        if scenario_id == "S4":
            result = s4_quantum.evaluate(cfg)
            return ScenarioResult(
                scenario_id="S4",
                name="S4-Quantum",
                command=str(s4_quantum.build_openssl_command()),
                detected=result.detected,
                reported_success_rate=result.reported_success_rate,
                reported_fnr=result.reported_fnr,
                reported_response_ms=result.reported_response_ms,
                metrics={"min_score": result.min_score, "threshold": result.threshold},
            )
        # S5
        result = s5_evasion.evaluate(cfg)
        return ScenarioResult(
            scenario_id="S5",
            name="S5-Evasion",
            command=s5_evasion.build_command(),
            detected=result.detected,
            reported_success_rate=result.reported_success_rate,
            reported_fnr=result.reported_fnr,
            reported_response_ms=result.reported_response_ms,
            metrics={
                "mean_confidence_drop_pct": result.mean_confidence_drop_pct,
                "threshold_pct": result.threshold_pct,
            },
        )

    def run_all(self) -> list[ScenarioResult]:
        """Run S1–S5 in order and return the results."""
        return [self.run_scenario(sid) for sid in self.ORDER]


# --------------------------------------------------------------- module-level
def run_scenario(scenario_id: str, config: Any = None) -> ScenarioResult:
    runner = AttackRunner(configs={scenario_id: config} if config else None)
    return runner.run_scenario(scenario_id)


def run_all(configs: dict[str, Any] | None = None) -> list[ScenarioResult]:
    return AttackRunner(configs=configs).run_all()


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the attack runner."""
    import json
    results = run_all()
    print(json.dumps({
        "n_scenarios": len(results),
        "reported_table32": REPORTED_TABLE32,
        "results": [r.to_dict() for r in results],
    }, indent=2))
    return 0
