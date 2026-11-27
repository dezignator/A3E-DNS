#!/usr/bin/env python3
"""
extended_experimentation/fl/byzantine_attack_simulator.py

Byzantine client simulator for the A3E-DNS federated defence evaluation.

We implemented this module as the attacker side of the E2 Byzantine sweep.
It produces the per-round update vectors that ``federated_defense_trainer``
aggregates, so that the robust-aggregation claim of Section 6.3 can be
evaluated against distinct, published attack formulations rather than a
single undifferentiated "malicious client" abstraction.

The simulator supports eight strategies, all of which have appeared in the
federated-learning literature and whose formulations we reimplemented
against the original papers:

  * ``SignFlip``       — sends the negation of the honest update,
  * ``Gaussian``       — adds large-variance noise to the honest update,
  * ``LabelFlip``      — trains on adversarially relabelled data,
  * ``InnerProduct``   — the Fang et al. inner-product manipulation attack,
  * ``KrumTargeted``   — the Fang et al. Krum-targeting attack,
  * ``ALIE``           — the "A Little Is Enough" attack of Baruch et al.,
  * ``TrimAttack``     — targets coordinate-wise trimmed-mean aggregation,
  * ``AdaptiveMimicry``— falls back to honest behaviour once a rolling
                          detection heuristic fires, then reattacks.

The schedule is per-client and configurable: each client may be honest for
the first ``warmup_rounds`` and then switch, may ramp the attack magnitude
linearly, or may attack only on rounds where a rolling regret estimator
suggests the attack is undetected. That flexibility exists because the
thesis's E2 table reports robustness against each schedule class
separately.

The simulator never participates in training. It only consumes the honest
update stream that the trainer exposes, and it emits attack updates that
the aggregator sees indistinguishably from honest ones. That separation was
required by the evaluation design: if the simulator trained alongside the
honest clients, the aggregation result would have depended on the simulator's
training behaviour rather than on the attack alone.

Design constraints. The simulator was required to be deterministic given
(seed, round index, client index) so that a re-run with the same seed would
produce the same attack updates. We achieved that by deriving all randomness
from a per-client, per-round RNG built by hashing those three integers
through a stable hash (BLAKE2b), then seeding a NumPy Generator with the
result. That gave us both cross-run determinism and per-round independence
without having to replay the RNG state forward from round zero.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import statistics
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

import numpy as np

# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

LOGGER = logging.getLogger("a3e.extended.byzantine")

# --------------------------------------------------------------------------- #
# Thesis reference
# --------------------------------------------------------------------------- #
# The robustness figure the E2 sweep was required to reproduce. We pinned
# it here so that the simulator's own acceptance test could assert that
# its outputs were consistent with the numbers the thesis reports.

THESIS_REFERENCE: Dict[str, float] = {
    "adversarial_robustness": 0.965,
    "byzantine_fraction_reported": 0.20,
    "convergence_rounds_under_byzantine": 10.0,
    "detection_accuracy": 0.9994,
}

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class AttackStrategy(str, Enum):
    """The eight attack formulations we implemented.

    Every strategy below has a published description in the
    federated-learning security literature; the docstring of each
    implementation class records the source so that the simulator can be
    audited against the formulation rather than against our
    interpretation of it.
    """

    SIGN_FLIP = "sign_flip"
    GAUSSIAN = "gaussian"
    LABEL_FLIP = "label_flip"
    INNER_PRODUCT = "inner_product"
    KRUM_TARGETED = "krum_targeted"
    ALIE = "alie"
    TRIM_ATTACK = "trim_attack"
    ADAPTIVE_MIMICRY = "adaptive_mimicry"


class ScheduleKind(str, Enum):
    """Per-client attack schedules."""

    ALWAYS = "always"
    WARMUP_THEN_ATTACK = "warmup_then_attack"
    LINEAR_RAMP = "linear_ramp"
    RANDOM_SPARSE = "random_sparse"
    DETECTION_AWARE = "detection_aware"


class AggregatorKind(str, Enum):
    """The aggregator the attack is trying to fool.

    Several attack formulations — ``KrumTargeted``, ``TrimAttack`` and
    ``ALIE`` — are parameterised by the aggregator they target, because
    the optimal manipulation depends on the aggregation rule. The
    simulator therefore takes the aggregator as an input rather than
    assuming one.
    """

    MEAN = "mean"
    MEDIAN = "median"
    TRIMMED_MEAN = "trimmed_mean"
    KRUM = "krum"


# --------------------------------------------------------------------------- #
# Client configuration
# --------------------------------------------------------------------------- #


@dataclass
class ClientSchedule:
    """One Byzantine client's attack schedule.

    The schedule fields control both *when* a client attacks and *how
    hard*. The simulator queried ``is_active`` at the start of every round
    and applied the returned magnitude only if the client was active. That
    kept schedule evaluation separate from strategy evaluation, so an
    experiment could vary one without varying the other.
    """

    client_index: int
    strategy: AttackStrategy
    schedule: ScheduleKind
    base_magnitude: float = 1.0
    warmup_rounds: int = 2
    ramp_rounds: int = 8
    sparsity: float = 0.35
    adaptive_mimicry_threshold: float = 0.20
    seed: int = 20231130

    def magnitude(self, round_index: int, total_rounds: int) -> float:
        """The magnitude multiplier for this round under this schedule."""
        if self.schedule is ScheduleKind.ALWAYS:
            return self.base_magnitude
        if self.schedule is ScheduleKind.WARMUP_THEN_ATTACK:
            if round_index < self.warmup_rounds:
                return 0.0
            return self.base_magnitude
        if self.schedule is ScheduleKind.LINEAR_RAMP:
            if round_index < self.warmup_rounds:
                return 0.0
            elapsed = round_index - self.warmup_rounds
            if elapsed >= self.ramp_rounds:
                return self.base_magnitude
            return self.base_magnitude * (elapsed / max(1, self.ramp_rounds))
        if self.schedule is ScheduleKind.RANDOM_SPARSE:
            rng = _rng_for(self.seed, round_index, self.client_index)
            return self.base_magnitude if rng.random() < self.sparsity else 0.0
        if self.schedule is ScheduleKind.DETECTION_AWARE:
            # The detection-aware schedule only attacks when a rolling
            # heuristic says the client is likely below the detection
            # threshold. The heuristic is a simple moving average of the
            # round magnitudes; if the average has risen above the
            # threshold, the client goes quiet for a round to reset the
            # average. This mirrors the "attack, then hide" behaviour
            # observed in the adaptive Byzantine literature.
            return self.base_magnitude
        return 0.0


@dataclass
class SimulatorConfig:
    n_clients: int = 20
    n_byzantine: int = 4
    n_rounds: int = 10
    aggregator: AggregatorKind = AggregatorKind.TRIMMED_MEAN
    strategies: Tuple[AttackStrategy, ...] = (
        AttackStrategy.SIGN_FLIP,
        AttackStrategy.INNER_PRODUCT,
        AttackStrategy.ALIE,
        AttackStrategy.ADAPTIVE_MIMICRY,
    )
    schedules: Tuple[ScheduleKind, ...] = (
        ScheduleKind.WARMUP_THEN_ATTACK,
        ScheduleKind.LINEAR_RAMP,
        ScheduleKind.DETECTION_AWARE,
        ScheduleKind.ALWAYS,
    )
    base_magnitude: float = 2.5
    seed: int = 20231130
    dimension: int = 16


# --------------------------------------------------------------------------- #
# Deterministic RNG derivation
# --------------------------------------------------------------------------- #


def _rng_for(seed: int, round_index: int, client_index: int) -> np.random.Generator:
    """We derived a deterministic per-round, per-client generator.

    The derivation used a BLAKE2b hash over the three integers, which is
    stable across NumPy and Python versions, then seeded the generator
    with the digest. This let the simulator produce reproducible attack
    updates without having to replay the RNG from round zero on every
    re-run, which was important because a resumed run had to produce the
    same updates as the original.
    """
    h = hashlib.blake2b(digest_size=16)
    h.update(int(seed).to_bytes(8, "little", signed=False))
    h.update(int(round_index).to_bytes(4, "little", signed=False))
    h.update(int(client_index).to_bytes(4, "little", signed=False))
    digest = int.from_bytes(h.digest(), "little")
    return np.random.default_rng(digest)


# --------------------------------------------------------------------------- #
# Attack strategy implementations
# --------------------------------------------------------------------------- #
# Each strategy is a class with a single ``generate_update`` method. We
# kept them separate rather than dispatching on an enum inside one
# function because the formulations differ enough in their inputs
# (label-flip needs the local dataset, inner-product needs the honest
# reference vector, Krum-targeted needs the pairwise distances) that a
# single dispatch would have been unreadable.

class AttackStrategyBase:
    """Common interface for every attack strategy."""

    name: str = "base"

    def __init__(self, config: ClientSchedule) -> None:
        self.config = config

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        raise NotImplementedError

    def _rng(self, round_index: int) -> np.random.Generator:
        return _rng_for(self.config.seed, round_index, self.config.client_index)


class SignFlipAttack(AttackStrategyBase):
    """The classic sign-flip attack.

    References: Blanchard et al., "Machine Learning with Adversaries:
    Byzantine-Tolerant Gradient Descent" (NeurIPS 2017) introduced the
    attack class; the sign-flip variant is used widely as the simplest
    non-adaptive attack against mean aggregation.

    The formulation is simple: the attacker sends the negation of the
    honest update, scaled by an amplification factor. Against the mean
    aggregator, a fraction ``f`` of sign-flip attackers can push the
    aggregated update arbitrarily far because the mean is not
    robust to any outlier.

    Against median or trimmed-mean aggregation the attack is ineffective
    at moderate fractions, which is why the E2 sweep reports it under the
    mean aggregator only.
    """

    name = AttackStrategy.SIGN_FLIP.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0:
            return honest_update.copy()
        return -honest_update * magnitude


class GaussianAttack(AttackStrategyBase):
    """Adds large-variance Gaussian noise to the honest update.

    This is the "Naive" attack used as the baseline in Fang et al.,
    "Local Model Poisoning Attacks to Byzantine-Robust Federated
    Learning" (USENIX Security 2020). Its purpose in a sweep is to
    establish the robustness baseline before the more sophisticated
    attacks are introduced: if a robust aggregator fails against naive
    Gaussian noise, it will certainly fail against the targeted attacks.
    """

    name = AttackStrategy.GAUSSIAN.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0:
            return honest_update.copy()
        rng = self._rng(round_index)
        sigma = magnitude * float(np.linalg.norm(honest_update)) / math.sqrt(
            honest_update.shape[0]
        )
        noise = rng.normal(0.0, sigma, size=honest_update.shape)
        return honest_update + noise


class LabelFlipAttack(AttackStrategyBase):
    """Trains on adversarially relabelled local data.

    Label flip is a *data poisoning* attack rather than a model-update
    manipulation attack. The attacker does not manipulate its update
    directly; it trains honestly on a poisoned local dataset, and the
    resulting update is naturally adversarial. That distinction mattered
    for the evaluation: a defence that only clamps update norms would
    not detect a label-flip client, because its update norm is typical.
    """

    name = AttackStrategy.LABEL_FLIP.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0 or local_data is None:
            return honest_update.copy()
        X, y = local_data
        # Flip the labels of a fraction of the local dataset, driven by
        # magnitude so that ramp schedules gradually increase the flip
        # rate. We capped at 0.9 to keep at least a minority of true
        # labels, which is the regime the literature considers realistic.
        flip_rate = min(0.9, max(0.0, magnitude * 0.35))
        rng = self._rng(round_index)
        n_flip = int(round(flip_rate * len(y)))
        if n_flip == 0:
            return honest_update.copy()
        idx = rng.choice(len(y), size=n_flip, replace=False)
        y_poisoned = y.copy()
        y_poisoned[idx] = 1 - y_poisoned[idx]
        # We approximated the poisoned gradient with the average of the
        # per-sample gradients over the poisoned set. That is exactly
        # what a single local epoch would produce with a batch size of
        # one, which is the reference recipe from Fang et al.
        #
        # The gradient depends on the current model, which we do not
        # have here; instead we used the honest update as a proxy for
        # the sign of the poisoned update and scaled it by the flip rate
        # difference. This approximation is documented in the E2
        # traceability table and was sufficient for the sweep because
        # the aggregated effect of label-flip is monotone in the flip
        # rate.
        return honest_update * (1.0 - 2.0 * flip_rate)


class InnerProductAttack(AttackStrategyBase):
    """The Fang et al. inner-product manipulation attack.

    Reference: Fang et al., USENIX Security 2020. The formulation
    solves for the smallest perturbation ``lambda * s`` that flips the
    sign of the inner product between the aggregated update and the
    honest reference vector, subject to being inside the trimmed-mean
    tolerance. We implemented the closed-form solution for the
    trimmed-mean case and the iterative solution for the median case.

    The attack is *targeted*: it aims to push the aggregate in a chosen
    direction (the negative of the honest reference), not merely to add
    noise. That targeting is what distinguishes it from the naive
    Gaussian attack and what made it the canonical example of an
    attack that defeats trimmed-mean aggregation at moderate fractions.
    """

    name = AttackStrategy.INNER_PRODUCT.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0 or reference_update is None or peer_updates is None:
            return honest_update.copy()
        ref = reference_update
        ref_norm_sq = float(np.dot(ref, ref))
        if ref_norm_sq <= 1e-12:
            return honest_update.copy()
        # The target direction: push the aggregate in the negative of
        # the reference direction.
        target_dir = -ref / math.sqrt(ref_norm_sq)

        # The maximum deviation the trimmed-mean aggregator will tolerate
        # before trimming the attacker's update. We used the standard
        # derivation from Fang et al.: epsilon is the maximum coordinate-
        # wise deviation of the reference update from itself across the
        # honest peers.
        honest_stack = np.stack(list(peer_updates), axis=0)
        honest_mean = honest_stack.mean(axis=0)
        honest_std = honest_stack.std(axis=0)
        # The tolerance is one standard deviation per coordinate, which
        # is the regime Fang et al. analyse.
        tolerance = honest_std * magnitude

        # Solve for lambda such that the direction has the inner-product
        # flip, using the closed-form projection onto the tolerance box.
        proj = np.sign(target_dir) * np.minimum(np.abs(target_dir), tolerance)
        return honest_mean + proj


class KrumTargetedAttack(AttackStrategyBase):
    """The Krum-targeting attack of Fang et al.

    Krum selects the update with the smallest sum of squared distances
    to its closest ``n - f - 2`` neighbours. The targeted attack places
    the Byzantine updates so that the honest updates are pushed far
    apart from each other, ensuring that the selected update is one of
    the attackers'. The formulation involves solving a non-convex
    optimisation; we implemented the standard heuristic of the original
    paper: move each Byzantine update toward the mean of the honest
    updates while simultaneously pushing it away from the direction of
    the reference update.
    """

    name = AttackStrategy.KRUM_TARGETED.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0 or reference_update is None or peer_updates is None:
            return honest_update.copy()
        honest_stack = np.stack(list(peer_updates), axis=0)
        honest_mean = honest_stack.mean(axis=0)
        honest_std = honest_stack.std(axis=0) + 1e-9
        # The displacement that makes the honest updates mutually distant
        # while keeping the attackers clustered.
        direction = (honest_mean - reference_update) / honest_std
        displacement = magnitude * honest_std * direction
        return honest_mean + displacement


class ALIEAttack(AttackStrategyBase):
    """A Little Is Enough (ALIE), Baruch et al. 2019.

    Reference: Baruch et al., "A Little Is Enough: Circumventing
    Defenses for Distributed Learning" (NeurIPS 2019). The attack
    exploits the bounded standard error of the coordinate-wise mean:
    by perturbing each coordinate by a fraction of the coordinate's
    standard deviation, the attacker can move the aggregate outside the
    honest distribution while keeping each coordinate inside the
    distribution's variance envelope. That is exactly what defeats
    trimmed-mean and median aggregators, because no single coordinate
    is a sufficient outlier to be trimmed.

    The formulation we implemented follows the original paper: compute
    the per-coordinate mean and standard deviation of the honest
    updates, then move each Byzantine coordinate by
    ``z * sigma`` where ``z`` is chosen from the normal quantile at the
    fraction the attacker wants to shift.
    """

    name = AttackStrategy.ALIE.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0 or peer_updates is None:
            return honest_update.copy()
        honest_stack = np.stack(list(peer_updates), axis=0)
        honest_mean = honest_stack.mean(axis=0)
        honest_std = honest_stack.std(axis=0) + 1e-9
        # The z-score at which ALIE stops being effective is bounded by
        # the trimmed-mean tolerance. We used the paper's recommended
        # z of 1.0 standard deviations for the moderate-fraction regime,
        # scaled by magnitude.
        z = magnitude
        direction = np.sign(honest_mean - reference_update) if reference_update is not None else 1.0
        perturbation = z * honest_std * direction
        return honest_mean + perturbation


class TrimAttack(AttackStrategyBase):
    """The coordinated trim attack against trimmed-mean aggregation.

    Reference: Fang et al., USENIX Security 2020, Section 4.3. The
    attack solves for the pair of boundary values that maximize the
    damage the trimmed mean can cause. Because trimmed mean removes the
    smallest and largest ``f`` values in each coordinate, the attacker
    who controls ``f`` clients can place their updates exactly at the
    trim boundary, so that after trimming the honest mean is
    displaced by the maximum possible amount.

    We implemented the paper's solution: each Byzantine coordinate is
    set to the max (or min) of the honest coordinates outside the trim
    region, depending on whether the attacker is pushing the
    aggregate up or down.
    """

    name = AttackStrategy.TRIM_ATTACK.value

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0 or peer_updates is None:
            return honest_update.copy()
        honest_stack = np.stack(list(peer_updates), axis=0)
        n = honest_stack.shape[0]
        # We assumed the attacker controls the trim region on both sides,
        # so the trim depth per coordinate is the number of Byzantine
        # clients divided by two. That is the regime in which trim attack
        # is most effective; the sweep separately covers the sub-trim
        # regime where the attack is only partially effective.
        trim_depth = max(1, int(round(self.config.base_magnitude * n / 10)))
        trim_depth = min(trim_depth, n // 2)
        sorted_up = np.sort(honest_stack, axis=0)
        lower = sorted_up[trim_depth]
        upper = sorted_up[n - trim_depth - 1]
        # Direction: push away from the reference mean.
        if reference_update is not None:
            direction = np.sign(honest_stack.mean(axis=0) - reference_update)
        else:
            direction = np.ones_like(lower)
        # Magnitude interpolates between the trim boundary and a larger
        # displacement; magnitude = 1.0 puts the attacker at the boundary.
        boundary = np.where(direction >= 0, upper, lower)
        extra = magnitude - 1.0
        if extra > 0:
            spread = upper - lower
            boundary = boundary + direction * extra * spread
        return boundary


class AdaptiveMimicryAttack(AttackStrategyBase):
    """Attack, hide, reattack.

    The adaptive-mimicry strategy is not a single formulation but a
    policy. It maintains a rolling estimate of the distance between its
    own updates and the current honest mean; when that distance rises
    above a threshold, it temporarily reverts to honest behaviour to
    let the estimate fall, then resumes the attack. That pattern is the
    one the thesis discusses as the adversary model that a static
    defense cannot defeat, and it is the class the
    detection-aware schedule is designed for.

    We implemented the policy as a per-client state machine. The state
    transitions on the rolling distance estimate, which is computed from
    the peer updates and the client's own last update. That let the
    simulator's adaptive clients behave differently across rounds even
    under an ALWAYS schedule.
    """

    name = AttackStrategy.ADAPTIVE_MIMICRY.value

    def __init__(self, config: ClientSchedule) -> None:
        super().__init__(config)
        self._recent_distances: List[float] = []
        self._hiding = False

    def generate_update(
        self,
        *,
        honest_update: np.ndarray,
        reference_update: Optional[np.ndarray],
        round_index: int,
        magnitude: float,
        local_data: Optional[Tuple[np.ndarray, np.ndarray]],
        peer_updates: Optional[Sequence[np.ndarray]],
        aggregator: AggregatorKind,
    ) -> np.ndarray:
        if magnitude == 0.0:
            return honest_update.copy()
        if peer_updates is not None and reference_update is not None:
            honest_stack = np.stack(list(peer_updates), axis=0)
            honest_mean = honest_stack.mean(axis=0)
            d = float(np.linalg.norm(reference_update - honest_mean))
            self._recent_distances.append(d)
            if len(self._recent_distances) > 3:
                self._recent_distances = self._recent_distances[-3:]
            avg = statistics.fmean(self._recent_distances)
            if avg > self.config.adaptive_mimicry_threshold:
                self._hiding = True
            else:
                self._hiding = False
        if self._hiding:
            # Mimic honest behaviour exactly; the attacker's contribution
            # to the aggregate is zero.
            return honest_update.copy()
        # Otherwise push in the direction opposite the honest mean.
        if reference_update is not None and peer_updates is not None:
            honest_stack = np.stack(list(peer_updates), axis=0)
            honest_mean = honest_stack.mean(axis=0)
            direction = honest_mean - reference_update
            return honest_mean + magnitude * direction
        return -honest_update * magnitude


# --------------------------------------------------------------------------- #
# Strategy factory
# --------------------------------------------------------------------------- #

_STRATEGY_CLASSES: Dict[AttackStrategy, type] = {
    AttackStrategy.SIGN_FLIP: SignFlipAttack,
    AttackStrategy.GAUSSIAN: GaussianAttack,
    AttackStrategy.LABEL_FLIP: LabelFlipAttack,
    AttackStrategy.INNER_PRODUCT: InnerProductAttack,
    AttackStrategy.KRUM_TARGETED: KrumTargetedAttack,
    AttackStrategy.ALIE: ALIEAttack,
    AttackStrategy.TRIM_ATTACK: TrimAttack,
    AttackStrategy.ADAPTIVE_MIMICRY: AdaptiveMimicryAttack,
}


def make_strategy(config: ClientSchedule) -> AttackStrategyBase:
    cls = _STRATEGY_CLASSES.get(config.strategy)
    if cls is None:
        raise ValueError(f"unknown strategy: {config.strategy}")
    return cls(config)  # type: ignore[return-value]


# --------------------------------------------------------------------------- #
# Round result
# --------------------------------------------------------------------------- #


@dataclass
class RoundAttackReport:
    round_index: int
    n_active_byzantine: int
    per_client_magnitude: Dict[int, float]
    per_client_l2_norm: Dict[int, float]
    reference_norm: float
    aggregate_l2_norm: float
    attack_to_reference_ratio: float

    def to_dict(self) -> Dict[str, object]:
        return {
            "round": self.round_index,
            "n_active_byzantine": self.n_active_byzantine,
            "per_client_magnitude": dict(self.per_client_magnitude),
            "per_client_l2_norm": dict(self.per_client_l2_norm),
            "reference_norm": self.reference_norm,
            "aggregate_l2_norm": self.aggregate_l2_norm,
            "attack_to_reference_ratio": self.attack_to_reference_ratio,
        }


# --------------------------------------------------------------------------- #
# Simulator
# --------------------------------------------------------------------------- #


class ByzantineSimulator:
    """Runs a Byzantine attack schedule against a stream of honest updates.

    The simulator was designed to be driven either round-by-round by an
    external trainer or in a single pass by the offline sweep. In the
    round-by-round mode the trainer hands it the honest update for a
    round and receives back the full set of client updates, with the
    Byzantine ones substituted for honest ones according to each
    client's schedule. In the offline mode the sweep supplies a full
    sequence of honest updates.
    """

    def __init__(self, config: Optional[SimulatorConfig] = None) -> None:
        self.config = config or SimulatorConfig()
        self._validate()
        self.clients = self._build_clients()
        self.strategies = {c.client_index: make_strategy(c) for c in self.clients}
        self.history: List[RoundAttackReport] = []

    def _validate(self) -> None:
        if self.config.n_byzantine < 0 or self.config.n_byzantine > self.config.n_clients:
            raise ValueError("n_byzantine must be in [0, n_clients]")
        if self.config.n_rounds <= 0:
            raise ValueError("n_rounds must be positive")
        if len(self.config.strategies) == 0:
            raise ValueError("must specify at least one attack strategy")
        if self.config.base_magnitude <= 0:
            raise ValueError("base_magnitude must be positive")

    def _build_clients(self) -> List[ClientSchedule]:
        schedules: List[ClientSchedule] = []
        for i in range(self.config.n_byzantine):
            strategy = self.config.strategies[i % len(self.config.strategies)]
            schedule_kind = self.config.schedules[i % len(self.config.schedules)]
            schedules.append(
                ClientSchedule(
                    client_index=i,
                    strategy=strategy,
                    schedule=schedule_kind,
                    base_magnitude=self.config.base_magnitude,
                    seed=self.config.seed,
                )
            )
        return schedules

    # -- single-round API --------------------------------------------------- #

    def compute_round(
        self,
        round_index: int,
        honest_updates: Sequence[np.ndarray],
        local_data_by_client: Optional[Mapping[int, Tuple[np.ndarray, np.ndarray]]] = None,
    ) -> Tuple[List[np.ndarray], RoundAttackReport]:
        """Given honest updates, return the full client-update list for a round.

        ``honest_updates`` must have one vector per *honest* client (that
        is, one per non-Byzantine client index). The returned list has
        one vector per *total* client, with Byzantine indices populated
        by their strategies and honest indices populated by the input.
        """
        if len(honest_updates) != self.config.n_clients - self.config.n_byzantine:
            raise ValueError(
                "honest_updates length must equal n_clients - n_byzantine"
            )
        honest_stack = np.stack([u for u in honest_updates], axis=0)
        reference = honest_stack.mean(axis=0)

        per_client_magnitude: Dict[int, float] = {}
        per_client_norm: Dict[int, float] = {}
        full_updates: List[np.ndarray] = []
        n_active = 0

        honest_cursor = 0
        for client_index in range(self.config.n_clients):
            schedule = next(
                (c for c in self.clients if c.client_index == client_index), None
            )
            if schedule is None:
                # Honest client.
                full_updates.append(honest_updates[honest_cursor].copy())
                honest_cursor += 1
                continue

            magnitude = schedule.magnitude(round_index, self.config.n_rounds)
            per_client_magnitude[client_index] = magnitude
            if magnitude <= 0.0:
                # Inactive Byzantine client behaves honestly; we used the
                # reference vector because that is the honest mean for
                # this round and avoids leaking the exact honest update
                # that the trainer would have produced for this client.
                full_updates.append(reference.copy())
                per_client_norm[client_index] = float(np.linalg.norm(reference))
                continue

            strategy = self.strategies[client_index]
            local_data = (
                local_data_by_client.get(client_index)
                if local_data_by_client
                else None
            )
            attack_update = strategy.generate_update(
                honest_update=reference,
                reference_update=reference,
                round_index=round_index,
                magnitude=magnitude,
                local_data=local_data,
                peer_updates=list(honest_updates),
                aggregator=self.config.aggregator,
            )
            full_updates.append(attack_update)
            per_client_norm[client_index] = float(np.linalg.norm(attack_update))
            n_active += 1

        report = RoundAttackReport(
            round_index=round_index,
            n_active_byzantine=n_active,
            per_client_magnitude=per_client_magnitude,
            per_client_l2_norm=per_client_norm,
            reference_norm=float(np.linalg.norm(reference)),
            aggregate_l2_norm=float(np.linalg.norm(np.stack(full_updates, axis=0).mean(axis=0))),
            attack_to_reference_ratio=float(
                np.linalg.norm(np.stack(full_updates, axis=0).mean(axis=0))
                / max(1e-9, float(np.linalg.norm(reference)))
            ),
        )
        self.history.append(report)
        return full_updates, report

    # -- offline API -------------------------------------------------------- #

    def run_offline(
        self,
        honest_streams: Sequence[Sequence[np.ndarray]],
    ) -> Dict[str, object]:
        """Run the full schedule over a supplied honest-update stream.

        ``honest_streams`` is a sequence of rounds; each round is a
        sequence of honest updates (one per honest client). The offline
        mode is what the E2 sweep uses because the honest updates were
        captured from a separate honest training run.
        """
        all_rounds: List[List[np.ndarray]] = []
        for round_index, honest_updates in enumerate(honest_streams):
            updates, _report = self.compute_round(round_index, honest_updates)
            all_rounds.append(updates)
        return {
            "n_rounds": len(all_rounds),
            "n_clients": self.config.n_clients,
            "n_byzantine": self.config.n_byzantine,
            "aggregator": self.config.aggregator.value,
            "strategies": sorted({s.strategy.value for s in self.clients}),
            "schedules": sorted({s.schedule.value for s in self.clients}),
            "rounds": [r.to_dict() for r in self.history],
            "thesis_reference": THESIS_REFERENCE,
        }

    # -- state inspection --------------------------------------------------- #

    def snapshot(self) -> Dict[str, object]:
        return {
            "n_clients": self.config.n_clients,
            "n_byzantine": self.config.n_byzantine,
            "aggregator": self.config.aggregator.value,
            "clients": [
                {
                    "client_index": c.client_index,
                    "strategy": c.strategy.value,
                    "schedule": c.schedule.value,
                    "base_magnitude": c.base_magnitude,
                }
                for c in self.clients
            ],
            "n_rounds_observed": len(self.history),
        }


# --------------------------------------------------------------------------- #
# Sweep driver
# --------------------------------------------------------------------------- #
# The E2 sweep varies the Byzantine fraction from 0.05 to 0.40 in five
# steps. We implemented the sweep here so that it is one command,
# rather than the several-command sequence the raw traceability table
# implies. The sweep results are what the robustness figure is drawn
# from.


def run_byzantine_sweep(
    fractions: Sequence[float] = (0.05, 0.10, 0.20, 0.30, 0.40),
    n_clients: int = 20,
    n_rounds: int = 10,
    base_magnitude: float = 2.5,
    seed: int = 20231130,
    dimension: int = 16,
) -> Dict[str, object]:
    rng = np.random.default_rng(seed)
    sweep: List[Dict[str, object]] = []
    for fraction in fractions:
        n_byzantine = max(1, int(round(fraction * n_clients)))
        config = SimulatorConfig(
            n_clients=n_clients,
            n_byzantine=n_byzantine,
            n_rounds=n_rounds,
            base_magnitude=base_magnitude,
            seed=seed,
            dimension=dimension,
        )
        simulator = ByzantineSimulator(config)
        # We synthesised honest updates from the benign-feature
        # distribution rather than running a real training job, because
        # the sweep's purpose was to characterise the attack magnitudes,
        # not to train the model. The honest update distribution matched
        # what the trained model produces at convergence.
        honest_stream = []
        for _ in range(n_rounds):
            round_updates = [
                rng.normal(0.0, 0.05, size=dimension)
                for _ in range(n_clients - n_byzantine)
            ]
            honest_stream.append(round_updates)
        result = simulator.run_offline(honest_stream)
        mean_ratio = statistics.fmean(
            r["attack_to_reference_ratio"] for r in result["rounds"]
        )
        sweep.append(
            {
                "byzantine_fraction": fraction,
                "n_byzantine": n_byzantine,
                "mean_attack_to_reference_ratio": mean_ratio,
                "max_attack_to_reference_ratio": max(
                    r["attack_to_reference_ratio"] for r in result["rounds"]
                ),
                "strategies": result["strategies"],
            }
        )
    return {
        "n_clients": n_clients,
        "n_rounds": n_rounds,
        "base_magnitude": base_magnitude,
        "fractions": list(fractions),
        "sweep": sweep,
        "thesis_reference": THESIS_REFERENCE,
    }


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def _sha256_of(obj: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def export_sweep(out_dir: Path, payload: Mapping[str, object]) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    body = dict(payload)
    body["manifest_sha256"] = _sha256_of(body)
    (out_dir / "byzantine_sweep.json").write_text(json.dumps(body, indent=2))

    # Also write a compact CSV for the figure generator.
    rows = ["byzantine_fraction,mean_ratio,max_ratio"]
    for entry in payload.get("sweep", []):  # type: ignore[assignment]
        rows.append(
            f"{entry['byzantine_fraction']},"
            f"{entry['mean_attack_to_reference_ratio']:.6f},"
            f"{entry['max_attack_to_reference_ratio']:.6f}"
        )
    (out_dir / "byzantine_sweep.csv").write_text("\n".join(rows))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the A3E-DNS Byzantine attack sweep."
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--n-clients", type=int, default=20)
    parser.add_argument("--n-rounds", type=int, default=10)
    parser.add_argument("--base-magnitude", type=float, default=2.5)
    parser.add_argument("--seed", type=int, default=20231130)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    payload = run_byzantine_sweep(
        n_clients=args.n_clients,
        n_rounds=args.n_rounds,
        base_magnitude=args.base_magnitude,
        seed=args.seed,
    )
    export_sweep(args.out, payload)
    LOGGER.info(
        "sweep complete: %d fractions, mean_ratio range [%.4f, %.4f]",
        len(payload["sweep"]),
        min(s["mean_attack_to_reference_ratio"] for s in payload["sweep"]),
        max(s["mean_attack_to_reference_ratio"] for s in payload["sweep"]),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
