#!/usr/bin/env python3
"""
extended_experimentation/attack_scenarios/a3e_attack_catalogue.py

Feature-level attack scenario generator for the A3E-DNS Chapter 6
evaluation.

We implemented this module to reproduce the scenario catalogue that the
thesis describes in Section 6.2.2 and Tables 30–32. Every scenario is
defined at the flow-feature level, so the detector is evaluated on the same
sixteen-feature representation that the production pipeline uses. We did
not launch live attack tools; the catalogue is a controlled simulation of
the feature shifts that each tool produces, as the traceability document
records.

Each scenario has three variants:

  * baseline — the nominal severity-1 shift;
  * low-and-slow — the same shift spread over a longer horizon;
  * adaptive blend — the shift partially reverted toward benign statistics.

The generator emits one row per flow window, with a ground-truth label and
the scenario identifier. The evaluation suite consumes these rows directly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.attack_catalogue")

# --------------------------------------------------------------------------- #
# Thesis reference values
# --------------------------------------------------------------------------- #

THESIS_REFERENCE: Dict[str, float] = {
    "detection_accuracy": 0.9994,
    "false_positive_rate_fraction": 0.0017,
    "p99_latency_ms": 1.42,
    "adversarial_robustness": 0.965,
    "differential_privacy_epsilon": 0.68,
    "peak_throughput_qps": 22_500_000,
}

# --------------------------------------------------------------------------- #
# Feature schema
# --------------------------------------------------------------------------- #
# We fixed the sixteen-feature schema before any scenario was generated so
# that every downstream stage consumed the same representation. The names
# match the ones in src/a3e_dns_v2/traffic.py.

FEATURE_NAMES: Tuple[str, ...] = (
    "iat_mean_ms",
    "iat_std_ms",
    "iat_skew",
    "pkt_size_mean",
    "pkt_size_std",
    "qname_entropy_bits",
    "subdomain_len_mean",
    "unique_name_ratio",
    "query_rate_per_s",
    "stream_count",
    "payload_entropy_bits",
    "handshake_ms",
    "proto_anomaly_score",
    "response_size_mean",
    "ttl_mean_s",
    "direction_ratio",
)

N_FEATURES = len(FEATURE_NAMES)

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Protocol(str, Enum):
    DOH = "doh"
    DOT = "dot"
    DOQ = "doq"


class ScenarioFamily(str, Enum):
    TIMING = "timing"
    TUNNEL = "tunnel"
    QUANTUM = "quantum"
    EVASION = "evasion"
    STREAM_MUX = "stream_mux"
    BEACON = "beacon"
    FRAGMENTATION = "fragmentation"
    PADDING_ABUSE = "padding_abuse"
    CACHE_POISON = "cache_poison"
    SIDE_CHANNEL = "side_channel"


class Variant(str, Enum):
    BASELINE = "baseline"
    LOW_AND_SLOW = "low_and_slow"
    ADAPTIVE_BLEND = "adaptive_blend"


# --------------------------------------------------------------------------- #
# Scenario definition
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FeatureShift:
    """A single-feature additive or multiplicative shift at severity 1."""

    feature: str
    delta: float
    multiplicative: bool = False

    def apply(self, base: float, severity: float) -> float:
        if self.multiplicative:
            return base * (1.0 + self.delta * severity)
        return base + self.delta * severity


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str
    family: ScenarioFamily
    protocols: Tuple[Protocol, ...]
    shifts: Tuple[FeatureShift, ...]
    description: str
    reference: str  # Chapter 6 table reference

    def severity_scale(self, variant: Variant) -> float:
        if variant is Variant.BASELINE:
            return 1.0
        if variant is Variant.LOW_AND_SLOW:
            return 0.45
        if variant is Variant.ADAPTIVE_BLEND:
            return 0.65
        raise ValueError(variant)


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #
# We transcribed the catalogue from 04_attack_scenario_catalogue.md. The
# scenario identifiers are identical so that a row in the generated data can
# be traced back to the thesis table.

CATALOGUE: Tuple[ScenarioDefinition, ...] = (
    ScenarioDefinition(
        scenario_id="S1-Timing",
        family=ScenarioFamily.TIMING,
        protocols=(Protocol.DOH, Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("iat_mean_ms", 1.6),
            FeatureShift("iat_skew", 2.4),
            FeatureShift("iat_std_ms", 0.8),
        ),
        description="Inter-arrival distribution drifts right-skewed under timing inference.",
        reference="Table 32 S1; Table 30 row 1",
    ),
    ScenarioDefinition(
        scenario_id="S2-Tunnel",
        family=ScenarioFamily.TUNNEL,
        protocols=(Protocol.DOH, Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("qname_entropy_bits", 3.2),
            FeatureShift("subdomain_len_mean", 3.4),
            FeatureShift("unique_name_ratio", 3.0),
            FeatureShift("pkt_size_std", -1.0),
            FeatureShift("query_rate_per_s", 1.2),
        ),
        description="High-entropy, long, mostly unique labels at a steady low rate.",
        reference="Table 32 S2; Table 31 'Encrypted Tunnel'",
    ),
    ScenarioDefinition(
        scenario_id="S4-Quantum",
        family=ScenarioFamily.QUANTUM,
        protocols=(Protocol.DOH, Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("handshake_ms", 2.2),
            FeatureShift("proto_anomaly_score", 4.0),
        ),
        description="Handshake with non-negotiated or malformed PQ key-exchange parameters.",
        reference="Table 32 S4; Table 30 'QUIC Version Downgrade'",
    ),
    ScenarioDefinition(
        scenario_id="S5-Evasion",
        family=ScenarioFamily.EVASION,
        protocols=(Protocol.DOH, Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("qname_entropy_bits", 1.5),
            FeatureShift("subdomain_len_mean", 1.4),
            FeatureShift("unique_name_ratio", 1.4),
            FeatureShift("pkt_size_std", -0.4),
        ),
        description="Tunnel traffic perturbed toward benign statistics.",
        reference="Table 32 S5; Table 30 'Adversarial Query Crafting'",
    ),
    ScenarioDefinition(
        scenario_id="S6-Beacon",
        family=ScenarioFamily.BEACON,
        protocols=(Protocol.DOH, Protocol.DOQ),
        shifts=(
            FeatureShift("iat_std_ms", -0.6),
            FeatureShift("query_rate_per_s", 0.9),
            FeatureShift("response_size_mean", -0.3),
        ),
        description="Periodic command-and-control beacon with low timing variance.",
        reference="Table 31 'C2 Beacon'",
    ),
    ScenarioDefinition(
        scenario_id="S7-Fragmentation",
        family=ScenarioFamily.FRAGMENTATION,
        protocols=(Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("pkt_size_std", 1.1),
            FeatureShift("response_size_mean", -0.5),
            FeatureShift("stream_count", 0.8),
        ),
        description="Payload fragmented across many small responses.",
        reference="Table 31 'Fragment Evasion'",
    ),
    ScenarioDefinition(
        scenario_id="S8-PaddingAbuse",
        family=ScenarioFamily.PADDING_ABUSE,
        protocols=(Protocol.DOH, Protocol.DOT),
        shifts=(
            FeatureShift("pkt_size_mean", 1.7, multiplicative=True),
            FeatureShift("pkt_size_std", -0.7),
            FeatureShift("payload_entropy_bits", -0.4),
        ),
        description="Excessive padding used to hide payload boundaries.",
        reference="Table 31 'Padding Oracle'",
    ),
    ScenarioDefinition(
        scenario_id="S9-CachePoison",
        family=ScenarioFamily.CACHE_POISON,
        protocols=(Protocol.DOH, Protocol.DOT, Protocol.DOQ),
        shifts=(
            FeatureShift("ttl_mean_s", -2.2),
            FeatureShift("unique_name_ratio", 1.9),
            FeatureShift("response_size_mean", 0.6),
        ),
        description="Low-TTL records injected to force cache eviction.",
        reference="Table 31 'Cache Poisoning'",
    ),
    ScenarioDefinition(
        scenario_id="S10-SideChannel",
        family=ScenarioFamily.SIDE_CHANNEL,
        protocols=(Protocol.DOH, Protocol.DOQ),
        shifts=(
            FeatureShift("iat_std_ms", 1.3),
            FeatureShift("payload_entropy_bits", 0.9),
            FeatureShift("direction_ratio", 0.4),
        ),
        description="Timing and direction patterns consistent with a side channel.",
        reference="Table 32 S10",
    ),
    ScenarioDefinition(
        scenario_id="DoH-MUX",
        family=ScenarioFamily.STREAM_MUX,
        protocols=(Protocol.DOH,),
        shifts=(
            FeatureShift("stream_count", 3.0),
            FeatureShift("payload_entropy_bits", 1.4),
            FeatureShift("pkt_size_std", 1.2),
        ),
        description="Malicious queries hidden in one HTTP/2 stream among legitimate ones.",
        reference="Table 31 'HTTP/2 Multiplexing'",
    ),
)

CATALOGUE_BY_ID: Dict[str, ScenarioDefinition] = {
    s.scenario_id: s for s in CATALOGUE
}

# --------------------------------------------------------------------------- #
# Benign baseline
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BenignBaseline:
    """Mean and standard deviation of the benign feature distribution."""

    mean: np.ndarray
    std: np.ndarray

    def sample(self, rng: np.random.Generator) -> np.ndarray:
        return rng.normal(self.mean, self.std)

    @staticmethod
    def default() -> "BenignBaseline":
        # We derived these moments from the benign partition of the
        # CIC-DoHBrw-2020 loader in the base repository. They are stated
        # here as constants so that the catalogue is reproducible without
        # the loader.
        mean = np.array(
            [
                24.5,   # iat_mean_ms
                18.2,   # iat_std_ms
                0.42,   # iat_skew
                312.0,  # pkt_size_mean
                96.0,   # pkt_size_std
                2.1,    # qname_entropy_bits
                12.4,   # subdomain_len_mean
                0.21,   # unique_name_ratio
                3.8,    # query_rate_per_s
                1.0,    # stream_count
                5.6,    # payload_entropy_bits
                34.0,   # handshake_ms
                0.08,   # proto_anomaly_score
                286.0,  # response_size_mean
                180.0,  # ttl_mean_s
                0.52,   # direction_ratio
            ],
            dtype=np.float64,
        )
        std = np.array(
            [
                9.1, 7.4, 0.28, 68.0, 31.0, 0.55, 3.8, 0.09,
                1.4, 0.15, 0.9, 8.5, 0.04, 52.0, 62.0, 0.08,
            ],
            dtype=np.float64,
        )
        return BenignBaseline(mean=mean, std=std)


# --------------------------------------------------------------------------- #
# Scenario row
# --------------------------------------------------------------------------- #


@dataclass
class ScenarioRow:
    flow_id: str
    window_id: str
    scenario_id: Optional[str]
    family: Optional[str]
    protocol: str
    variant: str
    label: int
    severity: float
    features: np.ndarray

    def to_dict(self) -> Dict[str, object]:
        return {
            "flow_id": self.flow_id,
            "window_id": self.window_id,
            "scenario_id": self.scenario_id,
            "family": self.family,
            "protocol": self.protocol,
            "variant": self.variant,
            "label": int(self.label),
            "severity": float(self.severity),
            **{name: float(self.features[i]) for i, name in enumerate(FEATURE_NAMES)},
        }


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #


@dataclass
class CatalogueConfig:
    seed: int = 20231130
    benign_windows_per_protocol: int = 2_000
    attack_windows_per_scenario_variant: int = 500
    window_size_packets: int = 32
    protocols: Tuple[Protocol, ...] = (Protocol.DOH, Protocol.DOT, Protocol.DOQ)


class AttackCatalogueGenerator:
    def __init__(self, config: Optional[CatalogueConfig] = None) -> None:
        self.config = config or CatalogueConfig()
        self.rng = np.random.default_rng(self.config.seed)
        self.baseline = BenignBaseline.default()

    # -- benign ------------------------------------------------------------- #

    def _benign_windows(self) -> List[ScenarioRow]:
        rows: List[ScenarioRow] = []
        for protocol in self.config.protocols:
            for i in range(self.config.benign_windows_per_protocol):
                features = np.clip(
                    self.baseline.sample(self.rng),
                    a_min=np.zeros(N_FEATURES),
                    a_max=None,
                )
                rows.append(
                    ScenarioRow(
                        flow_id=f"benign-{protocol.value}-{i:06d}",
                        window_id=f"w-{i:06d}",
                        scenario_id=None,
                        family=None,
                        protocol=protocol.value,
                        variant="benign",
                        label=0,
                        severity=0.0,
                        features=features,
                    )
                )
        return rows

    # -- attack ------------------------------------------------------------- #

    def _attack_windows(
        self,
        scenario: ScenarioDefinition,
        variant: Variant,
        protocol: Protocol,
    ) -> List[ScenarioRow]:
        severity = scenario.severity_scale(variant)
        rows: List[ScenarioRow] = []
        for i in range(self.config.attack_windows_per_scenario_variant):
            features = self.baseline.sample(self.rng).copy()
            for shift in scenario.shifts:
                idx = FEATURE_NAMES.index(shift.feature)
                features[idx] = shift.apply(features[idx], severity)
            # We applied a multiplicative jitter to the full vector so that
            # attack windows are not deterministic translations of the
            # benign mean.
            features *= self.rng.lognormal(mean=0.0, sigma=0.05, size=N_FEATURES)
            features = np.clip(features, a_min=np.zeros(N_FEATURES), a_max=None)
            rows.append(
                ScenarioRow(
                    flow_id=f"{scenario.scenario_id}-{variant.value}-{protocol.value}-{i:06d}",
                    window_id=f"w-{i:06d}",
                    scenario_id=scenario.scenario_id,
                    family=scenario.family.value,
                    protocol=protocol.value,
                    variant=variant.value,
                    label=1,
                    severity=severity,
                    features=features,
                )
            )
        return rows

    # -- public API --------------------------------------------------------- #

    def generate(self) -> List[ScenarioRow]:
        rows: List[ScenarioRow] = self._benign_windows()
        for scenario in CATALOGUE:
            for variant in (Variant.BASELINE, Variant.LOW_AND_SLOW, Variant.ADAPTIVE_BLEND):
                for protocol in scenario.protocols:
                    rows.extend(
                        self._attack_windows(scenario, variant, protocol)
                    )
        self.rng.shuffle(rows)
        LOGGER.info("generated %d scenario rows", len(rows))
        return rows


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def export_catalogue(
    out_dir: Path,
    rows: Sequence[ScenarioRow],
    config: CatalogueConfig,
) -> Dict[str, object]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with (out_dir / "scenario_rows.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row.to_dict()) + "\n")

    feature_matrix = np.stack([r.features for r in rows])
    labels = np.array([r.label for r in rows], dtype=np.int64)
    np.savez_compressed(
        out_dir / "scenario_matrix.npz",
        features=feature_matrix,
        labels=labels,
        feature_names=np.array(FEATURE_NAMES, dtype=object),
    )

    manifest: Dict[str, object] = {
        "module": "extended_experimentation.attack_scenarios.a3e_attack_catalogue",
        "config": config.__dict__,
        "n_rows": len(rows),
        "n_benign": int((labels == 0).sum()),
        "n_attack": int((labels == 1).sum()),
        "scenarios": [s.scenario_id for s in CATALOGUE],
        "feature_names": list(FEATURE_NAMES),
        "thesis_reference": THESIS_REFERENCE,
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    LOGGER.info("exported catalogue with %d rows to %s", len(rows), out_dir)
    return manifest


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the A3E-DNS Chapter 6 attack scenario catalogue."
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20231130)
    parser.add_argument("--benign-per-protocol", type=int, default=2_000)
    parser.add_argument("--attack-per-variant", type=int, default=500)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config = CatalogueConfig(
        seed=args.seed,
        benign_windows_per_protocol=args.benign_per_protocol,
        attack_windows_per_scenario_variant=args.attack_per_variant,
    )
    generator = AttackCatalogueGenerator(config)
    rows = generator.generate()
    export_catalogue(args.out, rows, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
