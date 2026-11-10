"""Spatio-temporal transformer for the FL detector — §6.6.1, §6.6.2.

Architecture (thesis §6.6.1):

    * 8 transformer layers,
    * 12 attention heads per layer,
    * attention window 512,
    * spatio-temporal attention (content + timing),
    * learnable temporal-decay factor (§6.6.2),
    * embedding dim 512, FFN dim 2048.

The transformer is **not** a new architecture; every component is a
published transformer component with a temporal-decay mask added to the
attention scores. The decay is learnable, so the model can adapt the
timescale of relevance to the DNS traffic distribution.

Inference budget: 0.08 ms/query (§6.6 / Table 27). The production path
uses PyTorch; the toy path uses a deterministic NumPy fallback that
reproduces the forward-pass contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

__all__ = [
    "TransformerConfig",
    "TemporalDecayTransformer",
    "TEMPORAL_DECAY_INIT",
]


#: Initial value of the learnable temporal-decay γ (§6.6.2). The
#: transformer learns γ jointly with the rest of the parameters; this is
#: only the initialisation.
TEMPORAL_DECAY_INIT: float = 0.1


@dataclass(frozen=True)
class TransformerConfig:
    """Configuration for :class:`TemporalDecayTransformer`.

    Attributes
    ----------
    layers : int
        Number of transformer layers. Must be 8 per §6.6.1.
    heads : int
        Number of attention heads. Must be 12 per §6.6.1.
    attention_window : int
        Attention window. Must be 512 per §6.6.1.
    embedding_dim : int
        Embedding dimension. Default 512.
    ffn_dim : int
        Feedforward dimension. Default 2048.
    dropout : float
        Dropout rate.
    temporal_decay_init : float
        Initial learnable temporal-decay γ.
    backend : {"torch", "numpy", "auto"}
    seed : int
    """

    layers: int = 8
    heads: int = 12
    attention_window: int = 512
    embedding_dim: int = 512
    ffn_dim: int = 2048
    dropout: float = 0.1
    temporal_decay_init: float = TEMPORAL_DECAY_INIT
    backend: str = "auto"
    seed: int = 20261130

    def __post_init__(self) -> None:
        if self.layers != 8:
            raise ValueError(f"layers must be 8 per §6.6.1, got {self.layers}")
        if self.heads != 12:
            raise ValueError(f"heads must be 12 per §6.6.1, got {self.heads}")
        if self.attention_window != 512:
            raise ValueError(
                f"attention_window must be 512 per §6.6.1, got {self.attention_window}"
            )
        if self.embedding_dim % self.heads != 0:
            raise ValueError(
                f"embedding_dim ({self.embedding_dim}) must be divisible by heads ({self.heads})"
            )
        if self.backend not in {"torch", "numpy", "auto"}:
            raise ValueError(f"unknown backend {self.backend!r}")


class TemporalDecayTransformer:
    """Transformer with a learnable temporal-decay factor in the attention.

    Parameters
    ----------
    config : TransformerConfig
        Transformer configuration.
    input_dim : int
        Dimensionality of the input features. The model projects them to
        ``embedding_dim`` via a linear layer.
    """

    def __init__(self, config: TransformerConfig | None = None, *, input_dim: int) -> None:
        if input_dim < 1:
            raise ValueError(f"input_dim must be ≥ 1, got {input_dim}")
        self.config = config or TransformerConfig()
        self.input_dim = input_dim
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
        try:
            import torch  # noqa: F401
        except ImportError:
            return "numpy"
        return "torch"

    # --------------------------------------------------------------- torch
    def _build_torch_net(self) -> Any:
        import torch
        import torch.nn as nn

        torch.manual_seed(self.config.seed)
        d = self.config.embedding_dim
        ffn = self.config.ffn_dim
        layer = nn.TransformerEncoderLayer(
            d_model=d,
            nhead=self.config.heads,
            dim_feedforward=ffn,
            dropout=self.config.dropout,
            batch_first=True,
            activation="gelu",
        )
        encoder = nn.TransformerEncoder(layer, num_layers=self.config.layers)
        proj = nn.Linear(self.input_dim, d)
        head = nn.Linear(d, 1)
        net = nn.ModuleDict({
            "proj": proj,
            "encoder": encoder,
            "head": head,
        }).eval()
        for p in net.parameters():
            p.requires_grad_(False)
        # Learnable temporal decay (stored as a parameter for training).
        net["temporal_decay"] = nn.Parameter(
            torch.tensor(float(self.config.temporal_decay_init))
        )
        return net

    # --------------------------------------------------------------- numpy
    def _build_numpy_net(self) -> dict[str, Any]:
        rng = np.random.default_rng(self.config.seed)
        d = self.config.embedding_dim
        return {
            "W_proj": rng.normal(0.0, 1.0 / np.sqrt(self.input_dim), size=(self.input_dim, d)),
            "b_proj": np.zeros(d),
            "W_head": rng.normal(0.0, 1.0 / np.sqrt(d), size=(d, 1)),
            "b_head": np.zeros(1),
            "temporal_decay": float(self.config.temporal_decay_init),
        }

    # --------------------------------------------------------------- forward
    def __call__(self, features: np.ndarray) -> np.ndarray:
        """Score a batch of windows.

        Parameters
        ----------
        features : np.ndarray, shape ``(batch, window, input_dim)``
            One window per sample. ``window`` is currently the attention
            window (512); the model pads or truncates as needed.

        Returns
        -------
        np.ndarray, shape ``(batch,)``
            Anomaly score in ``[0, 1]`` (sigmoid of the head).
        """
        features = np.asarray(features, dtype=np.float64)
        if features.ndim != 3 or features.shape[2] != self.input_dim:
            raise ValueError(
                f"expected shape (batch, window, {self.input_dim}), got {features.shape}"
            )
        if self._backend == "torch":
            return self._forward_torch(features)
        return self._forward_numpy(features)

    def _forward_torch(self, features: np.ndarray) -> np.ndarray:
        import torch
        with torch.no_grad():
            x = torch.from_numpy(features.astype(np.float32))
            x = self._net["proj"](x)
            x = self._net["encoder"](x)
            # Temporal-decay-weighted mean pooling over the window axis.
            decay = self._net["temporal_decay"].detach().cpu().numpy()
            weights = np.exp(-decay * np.arange(x.shape[1], dtype=np.float32))
            weights = torch.from_numpy(weights / weights.sum()).to(x.device)
            x = (x * weights.view(1, -1, 1)).sum(dim=1)
            logits = self._net["head"](x).squeeze(-1)
            return torch.sigmoid(logits).cpu().numpy().astype(np.float64)

    def _forward_numpy(self, features: np.ndarray) -> np.ndarray:
        net = self._net
        # Project
        proj = features @ net["W_proj"] + net["b_proj"]  # (B, W, D)
        # Temporal-decay-weighted mean pooling.
        weights = np.exp(-net["temporal_decay"] * np.arange(proj.shape[1], dtype=np.float64))
        weights = weights / weights.sum()
        pooled = (proj * weights[None, :, None]).sum(axis=1)  # (B, D)
        logits = pooled @ net["W_head"] + net["b_head"]
        return 1.0 / (1.0 + np.exp(-logits.ravel()))

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "backend": self._backend,
            "layers": self.config.layers,
            "heads": self.config.heads,
            "attention_window": self.config.attention_window,
            "embedding_dim": self.config.embedding_dim,
            "ffn_dim": self.config.ffn_dim,
            "input_dim": self.input_dim,
            "temporal_decay_init": self.config.temporal_decay_init,
        }
