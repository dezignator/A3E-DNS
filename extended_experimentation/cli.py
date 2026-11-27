#!/usr/bin/env python3
"""
extended_experimentation/cli.py

Unified command-line interface for the A3E-DNS extended experimentation
suite.

We implemented this CLI as a thin dispatcher over the individual module
entry points. Each subcommand forwards its arguments unchanged to the
corresponding module's ``main`` and returns the exit code it produced.
That kept the individual modules independently runnable while giving the
suite a single discoverable entry point.

The subcommands mirror the pipeline order:

  generate-catalogue    a3e_attack_catalogue.main
  byzantine-sweep       byzantine_attack_simulator.main
  fl-train              federated_defense_trainer.main
  aee-trace             adaptive_evolutionary_encryption.main
  qhe-benchmark         quantum_safe_homomorphic_engine.main
  run-e1-e10            e1_e10_orchestrator.main
  pipeline-smoke        a3e_pipeline.main
  significance          a3e_statistical_harness.main
  ablation              a3e_ablation_runner.main
  tables                a3e_result_tables.main
  figures               a3e_figures.main
  load-dataset          a3e_dataset_loaders.main

We did not add an "all" subcommand. The pipeline stages have real
dependencies on each other's outputs, and a monolithic runner would have
made it too easy to start the whole pipeline with the wrong config. Each
subcommand accepted --out and its required inputs, so a shell script or
Makefile was the right place to sequence them.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys
from typing import Callable, Dict, List, Optional, Sequence

LOGGER = logging.getLogger("a3e.extended.cli")

SUBCOMMANDS: Dict[str, str] = {
    "generate-catalogue": "extended_experimentation.attack_scenarios.a3e_attack_catalogue",
    "byzantine-sweep": "extended_experimentation.fl.byzantine_attack_simulator",
    "fl-train": "extended_experimentation.fl.federated_defense_trainer",
    "aee-trace": "extended_experimentation.aee.adaptive_evolutionary_encryption",
    "qhe-benchmark": "extended_experimentation.qhe.quantum_safe_homomorphic_engine",
    "run-e1-e10": "extended_experimentation.experiments.e1_e10_orchestrator",
    "pipeline-smoke": "extended_experimentation.deployment.a3e_pipeline",
    "significance": "extended_experimentation.evaluation.a3e_statistical_harness",
    "ablation": "extended_experimentation.evaluation.a3e_ablation_runner",
    "tables": "extended_experimentation.reporting.a3e_result_tables",
    "figures": "extended_experimentation.reporting.a3e_figures",
    "load-dataset": "extended_experimentation.datasets.a3e_dataset_loaders",
}


def _resolve_main(module_path: str) -> Callable[[Optional[Sequence[str]]], int]:
    module = importlib.import_module(module_path)
    main = getattr(module, "main", None)
    if main is None:
        raise AttributeError(f"{module_path} has no main()")
    return main


def _split_at_verb(argv: Sequence[str]) -> tuple[str, List[str]]:
    for i, token in enumerate(argv):
        if token in SUBCOMMANDS:
            return token, list(argv[i + 1 :])
    raise SystemExit(
        f"expected one of {sorted(SUBCOMMANDS)} as the first non-flag argument"
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("A3E-DNS extended experimentation suite\n")
        print("Subcommands:")
        for verb in sorted(SUBCOMMANDS):
            print(f"  {verb:22s} {SUBCOMMANDS[verb]}")
        print("\nRun a subcommand with -h for its arguments.")
        return 0

    verb, forwarded = _split_at_verb(argv)
    module_path = SUBCOMMANDS[verb]
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    LOGGER.debug("dispatching %s -> %s", verb, module_path)
    sub_main = _resolve_main(module_path)
    return int(sub_main(forwarded))


if __name__ == "__main__":
    raise SystemExit(main())
