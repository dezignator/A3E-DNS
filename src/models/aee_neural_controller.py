"""Lightweight neural controller for AEE — thesis §6.4.5.

The controller realises the deterministic term ``F(·)`` of Eq. 119:

    dE(t)/dt = F(E(t), T(t), A(t)) + σ(t) dW_t

Architecture (thesis §6.4.5):

    * 2 hidden layers × 64 neurons each (2×64 MLP)
    * input window: 1000 packets
    * features: [size_moments, IAT_dist, entropy, protocol_attrs]
    * output: Lie-algebra update direction on ``SE(3)ⁿ`` (the caller
      exponentiates this)
    * training: reinforcement learning
    * inference budget: sub-microsecond, so the controller must not
      perturb the DNS resolution path.

Two backends are supported:

    * ``torch`` — the production path, ``torch.nn.Sequential`` MLP.
    * ``numpy`` — a deterministic fallback used by toy mode and by
      environments where torch is not installed. It reproduces the same
      input→output contract but is a fixed linear map, not a learned one.

The controller returns an ``(n, 6)`` array of Lie-algebra increments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

__all__ = [
    "ControllerConfig",
    "AEENeuralController",
    "HIDDEN_LAYERS",
    "NEURONS_PER_LAYER",
    "INPUT_WINDOW_PACKETS",
    "FEATURE_NAMES",
]

#: Thesis constants (§6.4.5). These are locked to the thesis and must not
#: be changed without updating the thesis artifact.
HIDDEN_LAYERS: int = 2
NEURONS_PER_LAYER: int = 64
INPUT_WINDOW_PACKETS: int = 1000
FEATURE_NAMES: tuple[str, ...] = (
    "size_moments",
    "iat_dist",
    "entropy",
    "protocol_attrs",
)


@dataclass(frozen=True)
class ControllerConfig:
    """Configuration for :class:`AEENeuralController`.

    Attributes
    ----------
    se3_dim : int
        Number of ``SE(3)`` factors, matching the AEE engine.
    feature_dim : int
        Dimensionality of the per-window feature vector. Defaults to
        ``len(FEATURE_NAMES) * 4`` so that each named feature contributes
        four numbers (mean, std, min, max) — the thesis's "moments" of
        the window.
    window : int
        Number of packets in the sliding window. Must be 1000.
    hidden_layers, neurons_per_layer : int
        Network size. Must match the thesis constants.
    backend : {"torch", "numpy", "auto"}
        Backend selector. ``"auto"`` uses torch when available, numpy
        otherwise.
    seed : int
        Master seed for parameter initialisation.
    """

    se3_dim: int = 1
    feature_dim: int = len(FEATURE_NAMES) * 4
    window: int = INPUT_WINDOW_PACKETS
    hidden_layers: int = HIDDEN_LAYERS
    neurons_per_layer: int = NEURONS_PER_LAYER
    backend: str = "auto"
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.se3_dim < 1:
            raise ValueError(f"se3_dim must be ≥ 1, got {self.se3_dim}")
        if self.feature_dim < 1:
            raise ValueError(f"feature_dim must be ≥ 1, got {self.feature_dim}")
        if self.window != INPUT_WINDOW_PACKETS:
            raise ValueError(
                f"window must be {INPUT_WINDOW_PACKETS} per §6.4.5, got {self.window}"
            )
        if self.hidden_layers != HIDDEN_LAYERS:
            raise ValueError(
                f"hidden_layers must be {HIDDEN_LAYERS} per §6.4.5, got {self.hidden_layers}"
            )
        if self.neurons_per_layer != NEURONS_PER_LAYER:
            raise ValueError(
                f"neurons_per_layer must be {NEURONS_PER_LAYER} per §6.4.5, "
                f"got {self.neurons_per_layer}"
            )
        if self.backend not in {"torch", "numpy", "auto"}:
            raise ValueError(f"unknown backend {self.backend!r}")


class AEENeuralController:
    """2×64 MLP that maps a traffic window to a Lie-algebra increment.

    Parameters
    ----------
    config : ControllerConfig
        Controller configuration.

    Notes
    -----
    * The controller is **not** a security module. It produces an update
      direction that the AEE engine exponentiates onto ``SE(3)ⁿ``.
    * Training uses reinforcement learning in the real system; this
      module ships the inference path only, with a fixed initialisation
      from ``src.utils.seed.rng_for``. The trained weights are recorded
      in the manifest and loaded by the production pipeline.
    """

    def __init__(self, config: ControllerConfig | None = None) -> None:
        self.config = config or ControllerConfig()
        self._backend = self._resolve_backend(self.config.backend)
        if self._backend == "torch":
            self._net = self._build_torch_net()
        else:
            self._net = self._build_numpy_net()

    # --------------------------------------------------------------- backend
    @staticmethod
    def _resolve_backend(requested: str) -> str:
        if requested == "numpy":
            return "numpy"
        if requested == "torch":
            try:
                import torch  # noqa: F401
            except ImportError as exc:
                raise ImportError("torch backend requested but torch is not installed") from exc
            return "torch"
        # auto
        try:
            import torch  # noqa: F401
        except ImportError:
            return "numpy"
        return "torch"

    # --------------------------------------------------------------- torch
    def _build_torch_net(self) -> Any:
        import torch  # local import to keep module import cheap
        import torch.nn as nn

        torch.manual_seed(self.config.seed)
        layers: list[nn.Module] = []
        in_dim = self.config.feature_dim
        for _ in range(self.config.hidden_layers):
            layers.append(nn.Linear(in_dim, self.config.neurons_per_layer))
            layers.append(nn.GELU())
            in_dim = self.config.neurons_per_layer
        layers.append(nn.Linear(in_dim, self.config.se3_dim * 6))
        net = nn.Sequential(*layers).eval()
        for p in net.parameters():
            p.requires_grad_(False)
        return net

    # --------------------------------------------------------------- numpy
    def _build_numpy_net(self) -> dict[str, np.ndarray]:
        rng = np.random.default_rng(self.config.seed)
        in_dim = self.config.feature_dim
        W1 = rng.normal(0.0, 1.0 / np.sqrt(in_dim), size=(in_dim, self.config.neurons_per_layer))
        b1 = np.zeros(self.config.neurons_per_layer)
        W2 = rng.normal(
            0.0, 1.0 / np.sqrt(self.config.neurons_per_layer),
            size=(self.config.neurons_per_layer, self.config.neurons_per_layer),
        )
        b2 = np.zeros(self.config.neurons_per_layer)
        W3 = rng.normal(
            0.0, 1.0 / np.sqrt(self.config.neurons_per_layer),
            size=(self.config.neurons_per_layer, self.config.se3_dim * 6),
        )
        b3 = np.zeros(self.config.se3_dim * 6)
        return {"W1": W1, "b1": b1, "W2": W2, "b2": b2, "W3": W3, "b3": b3}

    # --------------------------------------------------------------- infer
    def __call__(self, features: np.ndarray) -> np.ndarray:
        """Return the ``(n, 6)`` Lie-algebra increment for ``features``.

        ``features`` is either a 1-D vector of length ``feature_dim`` or a
        2-D array ``(batch, feature_dim)``. The output is always
        ``(se3_dim, 6)``; batch inputs are reduced by mean.
        """
        features = np.asarray(features, dtype=np.float64)
        if features.ndim == 1:
            x = features
        elif features.ndim == 2:
            x = features.mean(axis=0)
        else:
            raise ValueError(f"features must be 1-D or 2-D, got shape {features.shape}")
        if x.shape[0] != self.config.feature_dim:
            raise ValueError(
                f"feature_dim mismatch: expected {self.config.feature_dim}, got {x.shape[0]}"
            )
        if self._backend == "torch":
            return self._forward_torch(x)
        return self._forward_numpy(x)

    def _forward_torch(self, x: np.ndarray) -> np.ndarray:
        import torch
        with torch.no_grad():
            t = torch.from_numpy(x.astype(np.float32)).unsqueeze(0)
            y = self._net(t).squeeze(0).cpu().numpy().astype(np.float64)
        return y.reshape(self.config.se3_dim, 6)

    def _forward_numpy(self, x: np.ndarray) -> np.ndarray:
        net = self._net
        h1 = np.tanh(x @ net["W1"] + net["b1"])
        h2 = np.tanh(h1 @ net["W2"] + net["b2"])
        y = h2 @ net["W3"] + net["b3"]
        # Bound the output to a small magnitude so the SE(3) exponential
        # stays numerically stable in the toy mode.
        y = np.tanh(y) * 0.1
        return y.reshape(self.config.se3_dim, 6)

    # --------------------------------------------------------------- helpers
    def feature_vector(
        self,
        *,
        size_moments: Sequence[float],
        iat_dist: Sequence[float],
        entropy: Sequence[float],
        protocol_attrs: Sequence[float],
    ) -> np.ndarray:
        """Assemble a single ``feature_dim``-length vector from the four
        named inputs. Each input must supply exactly 4 numbers (mean,
        std, min, max), matching the default ``feature_dim``.
        """
        parts = (size_moments, iat_dist, entropy, protocol_attrs)
        for name, part in zip(FEATURE_NAMES, parts):
            if len(part) != 4:
                raise ValueError(f"{name} must have 4 values, got {len(part)}")
        return np.concatenate([np.asarray(p, dtype=np.float64) for p in parts])

    def metadata(self) -> dict[str, Any]:
        return {
            "backend": self._backend,
            "hidden_layers": self.config.hidden_layers,
            "neurons_per_layer": self.config.neurons_per_layer,
            "input_window_packets": self.config.window,
            "feature_names": list(FEATURE_NAMES),
            "feature_dim": self.config.feature_dim,
            "se3_dim": self.config.se3_dim,
        }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target (``python -m src --role aee-controller``).

    Kept intentionally minimal: it instantiates the controller, prints
    its metadata, and returns 0. The full AEE loop is driven by
    ``scripts/train_a3e.py``.
    """
    ctrl = AEENeuralController(ControllerConfig(backend="numpy" if device == "cpu" else "auto"))
    import json
    print(json.dumps(ctrl.metadata(), indent=2))
    return 0
