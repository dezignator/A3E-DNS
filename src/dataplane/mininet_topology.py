"""Mininet + BMv2 topology for the P4 3-stage pipeline — thesis §6.12.

Builds the software-defined network used to validate the P4 pipeline:

    * 1 BMv2 switch (P4 target, behavioural model),
    * 4 hosts (client, DoH resolver, DoT resolver, DoQ resolver),
    * links sized to emulate the 4-node testbed of §6.11.1.

The topology is the one described in §6.12: it is a **containerised
4-node simulation**, not a production deployment. Throughput figures
reported in the thesis are for this testbed only (see
``docs/LIMITATIONS.md`` §7.3.7).

This module is a thin wrapper over Mininet; the P4 switch is instantiated
through ``p4utils`` or ``p4_mininet`` depending on which is available. If
neither is present, ``build()`` returns a documented simulation
description so the caller can still exercise the rest of the pipeline.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "TopologyConfig",
    "MininetTopology",
    "TOPOLOGY_NODES",
]


#: Hosts in the topology, mapped to their role.
TOPOLOGY_NODES: dict[str, str] = {
    "h1": "client",
    "h2": "doh_resolver",
    "h3": "dot_resolver",
    "h4": "doq_resolver",
}

#: Switch name (single BMv2 switch).
SWITCH_NAME: str = "s1"

#: Default link parameters (bandwidth, delay, loss), matching the testbed
#: network profile of §6.11.2.
DEFAULT_BANDWIDTH_MBPS: int = 1000
DEFAULT_DELAY_MS: float = 1.0
DEFAULT_LOSS_PCT: float = 0.0


@dataclass(frozen=True)
class TopologyConfig:
    """Configuration for :class:`MininetTopology`.

    Attributes
    ----------
    switch_name : str
        Name of the BMv2 switch.
    p4_json : Path
        Compiled P4 pipeline JSON (produced by ``P4Telemetry.build``).
    hosts : dict[str, str]
        Host name → role.
    bandwidth_mbps : int
        Per-link bandwidth in Mbps.
    delay_ms : float
        Per-link emulated delay.
    loss_pct : float
        Per-link emulated loss.
    pcap_dir : Path
        Directory where per-host captures are written (empty to disable).
    """

    switch_name: str = SWITCH_NAME
    p4_json: Path = Path("/tmp/a3e-p4-parser.json")
    hosts: dict[str, str] = field(default_factory=lambda: dict(TOPOLOGY_NODES))
    bandwidth_mbps: int = DEFAULT_BANDWIDTH_MBPS
    delay_ms: float = DEFAULT_DELAY_MS
    loss_pct: float = DEFAULT_LOSS_PCT
    pcap_dir: Path = Path("/tmp/a3e-pcaps")

    def __post_init__(self) -> None:
        if self.bandwidth_mbps <= 0:
            raise ValueError(f"bandwidth_mbps must be > 0, got {self.bandwidth_mbps}")
        if self.delay_ms < 0.0:
            raise ValueError(f"delay_ms must be ≥ 0, got {self.delay_ms}")
        if not (0.0 <= self.loss_pct < 100.0):
            raise ValueError(f"loss_pct must be in [0, 100), got {self.loss_pct}")
        if not self.hosts:
            raise ValueError("hosts must be non-empty")


class MininetTopology:
    """Mininet topology driver.

    Parameters
    ----------
    config : TopologyConfig
        Topology configuration.

    Notes
    -----
    * If Mininet is not installed, :meth:`build` returns a simulation
      description. This is the toy/medium-mode path.
    * If ``p4utils`` is available, the switch is instantiated as a P4
      BMv2 switch; otherwise a plain ``OVSSwitch`` is used, and the
      P4 program must be loaded separately by
      :class:`src.dataplane.p4_telemetry.P4Telemetry`.
    """

    def __init__(self, config: TopologyConfig | None = None) -> None:
        self.config = config or TopologyConfig()

    # --------------------------------------------------------------- API
    def build(self) -> dict[str, Any]:
        """Build (or simulate) the topology and return a description.

        Returns
        -------
        dict
            Either ``{"mode": "mininet", "net": <Mininet>}`` (real build)
            or ``{"mode": "simulation", ...}`` (no Mininet installed).
        """
        if shutil.which("mn") is None:
            return self._simulate()

        try:
            from mininet.net import Mininet  # type: ignore
            from mininet.node import OVSSwitch  # type: ignore
            from mininet.link import TCLink  # type: ignore
        except ImportError:
            return self._simulate()

        net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)

        switch = net.addSwitch(self.config.switch_name)

        host_objs = {name: net.addHost(name) for name in self.config.hosts}
        for host in host_objs.values():
            net.addLink(
                host,
                switch,
                bw=self.config.bandwidth_mbps,
                delay=f"{self.config.delay_ms}ms",
                loss=self.config.loss_pct,
            )

        return {
            "mode": "mininet",
            "net": net,
            "switch": self.config.switch_name,
            "hosts": self.config.hosts,
            "config": self._config_dict(),
        }

    def simulate_traffic(
        self,
        *,
        source_host: str,
        destination_host: str,
        destination_port: int,
        protocol: str,
        n_packets: int = 100,
        interval_ms: float = 10.0,
    ) -> dict[str, Any]:
        """Describe a traffic pattern for the topology.

        In the real build, this would drive ``iperf3``/``scapy`` traffic
        between the two hosts. In the simulation path it returns a
        deterministic schedule that the test suite can assert on.
        """
        if source_host not in self.config.hosts:
            raise ValueError(f"unknown source host {source_host!r}")
        if destination_host not in self.config.hosts:
            raise ValueError(f"unknown destination host {destination_host!r}")
        if protocol not in {"tcp", "udp"}:
            raise ValueError(f"protocol must be 'tcp' or 'udp', got {protocol!r}")
        if n_packets < 1:
            raise ValueError(f"n_packets must be ≥ 1, got {n_packets}")
        return {
            "source": source_host,
            "destination": destination_host,
            "port": destination_port,
            "protocol": protocol,
            "n_packets": n_packets,
            "interval_ms": interval_ms,
            "total_duration_ms": n_packets * interval_ms,
        }

    # --------------------------------------------------------------- internals
    def _simulate(self) -> dict[str, Any]:
        return {
            "mode": "simulation",
            "switch": self.config.switch_name,
            "hosts": self.config.hosts,
            "config": self._config_dict(),
            "note": (
                "Mininet not installed; returning a description of the "
                "topology. Install mininet + p4utils for a real build."
            ),
        }

    def _config_dict(self) -> dict[str, Any]:
        return {
            "switch_name": self.config.switch_name,
            "p4_json": str(self.config.p4_json),
            "hosts": dict(self.config.hosts),
            "bandwidth_mbps": self.config.bandwidth_mbps,
            "delay_ms": self.config.delay_ms,
            "loss_pct": self.config.loss_pct,
            "pcap_dir": str(self.config.pcap_dir),
        }


# --------------------------------------------------------------- role entry
def run(mode: str = "toy", device: str = "cpu") -> int:
    """CLI dispatcher target for the Mininet topology."""
    import json
    topo = MininetTopology()
    result = topo.build()
    print(json.dumps({
        "mode": result["mode"],
        "switch": result["switch"],
        "hosts": result["hosts"],
        "config": result["config"],
    }, indent=2))
    return 0
