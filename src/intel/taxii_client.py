"""TAXII 2.1 client for CERT-alert transport — thesis §6.7.1.

TAXII 2.1 transports STIX 2.1 over HTTPS with a REST API. The client is
a thin wrapper over ``taxii2-client``; the contribution of this module
is the operational integration into the A³E-DNS pipeline, not the TAXII
protocol (published as OASIS TAXII 2.1).

For the toy and medium reproduction modes, the client reads a local
JSON fixture instead of connecting to a live TAXII server. For the full
mode it uses the ``taxii2-client`` dependency with configurable
credentials via environment variables:

    TAXII_SERVER_URL
    TAXII_COLLECTION_ID
    TAXII_USER
    TAXII_PASSWORD

The client deliberately never writes raw STIX to disk outside
``data/threat_feeds/``; STIX objects are held in memory and passed to
:class:`src.intel.stix_parser.STIXParser`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from src.intel.stix_parser import IntelRecord, STIXParser, parse_stix_file

__all__ = [
    "TAXIIConfig",
    "TAXIIClient",
    "TAXIIConnectionError",
]


# --------------------------------------------------------------- config
@dataclass(frozen=True)
class TAXIIConfig:
    """Configuration for :class:`TAXIIClient`.

    Attributes
    ----------
    server_url : str | None
        TAXII 2.1 server base URL. If ``None`` (toy / medium), the client
        reads the local fixture ``sample_path`` instead.
    collection_id : str | None
        TAXII collection identifier.
    user, password : str | None
        Basic-auth credentials. Prefer environment variables
        (``TAXII_USER``, ``TAXII_PASSWORD``) over literals.
    sample_path : Path
        Local fixture used when ``server_url`` is ``None``.
    verify_tls : bool
        Whether to verify the server's TLS certificate. Default ``True``.
    timeout_s : float
        Per-request timeout.
    """

    server_url: str | None = None
    collection_id: str | None = None
    user: str | None = None
    password: str | None = None
    sample_path: Path = Path("data/threat_feeds/cert_alerts_sample.stix.json")
    verify_tls: bool = True
    timeout_s: float = 30.0

    @classmethod
    def from_env(cls) -> "TAXIIConfig":
        """Build a config from ``TAXII_*`` environment variables."""
        return cls(
            server_url=os.environ.get("TAXII_SERVER_URL") or None,
            collection_id=os.environ.get("TAXII_COLLECTION_ID") or None,
            user=os.environ.get("TAXII_USER") or None,
            password=os.environ.get("TAXII_PASSWORD") or None,
        )

    def __post_init__(self) -> None:
        if self.timeout_s <= 0.0:
            raise ValueError(f"timeout_s must be > 0, got {self.timeout_s}")


# --------------------------------------------------------------- errors
class TAXIIConnectionError(RuntimeError):
    """Raised when a live TAXII request fails."""


# --------------------------------------------------------------- client
class TAXIIClient:
    """TAXII 2.1 client with a local-fixture fallback.

    Parameters
    ----------
    config : TAXIIConfig
        Client configuration.
    """

    def __init__(self, config: TAXIIConfig | None = None) -> None:
        self.config = config or TAXIIConfig()
        self._parser = STIXParser(validate=True)
        self._taxii = None
        if self.config.server_url is not None:
            try:
                from taxii2client.v21 import Collection, Server  # type: ignore
            except ImportError as exc:
                raise ImportError(
                    "live TAXII mode requires the 'taxii2-client' package; "
                    "install requirements.txt or set server_url=None to use the local fixture"
                ) from exc
            self._taxii = (Server, Collection)

    # --------------------------------------------------------------- API
    def fetch(self) -> list[IntelRecord]:
        """Fetch and parse the current CERT alerts.

        Returns
        -------
        list[IntelRecord]
            One record per STIX indicator. Duplicates are not removed
            here; the pipeline de-duplicates downstream.
        """
        if self.config.server_url is None:
            return self._fetch_local()
        return self._fetch_live()

    # --------------------------------------------------------------- local
    def _fetch_local(self) -> list[IntelRecord]:
        path = Path(self.config.sample_path)
        if not path.exists():
            return []
        return parse_stix_file(path)

    # --------------------------------------------------------------- live
    def _fetch_live(self) -> list[IntelRecord]:
        assert self._taxii is not None
        Server, Collection = self._taxii

        auth = None
        if self.config.user and self.config.password:
            auth = (self.config.user, self.config.password)

        try:
            server = Server(self.config.server_url, user=self.config.user, password=self.config.password)
            collection = Collection(
                f"{self.config.server_url.rstrip('/')}/collections/{self.config.collection_id}/",
                user=self.config.user,
                password=self.config.password,
            )
            bundle = collection.get_objects()
        except Exception as exc:  # noqa: BLE001 - taxii2-client raises many types
            raise TAXIIConnectionError(f"TAXII fetch failed: {exc}") from exc

        # taxii2-client returns a dict-like bundle.
        return self._parser.parse_bundle(bundle)

    # --------------------------------------------------------------- metadata
    def metadata(self) -> dict[str, Any]:
        return {
            "mode": "live" if self.config.server_url else "local-fixture",
            "server_url": self.config.server_url,
            "collection_id": self.config.collection_id,
            "sample_path": str(self.config.sample_path),
            "verify_tls": self.config.verify_tls,
            "timeout_s": self.config.timeout_s,
        }
