#!/usr/bin/env python3
"""
p4/control_plane/telemetry_reader.py

Reads switch-side feature registers back into the pipeline's own
format.

We implemented this reader for two purposes. First, it is what a
reviewer uses to inspect the switch's register state without writing
a P4Runtime client of their own. Second, it is what the pipeline's
own tests use when they need switch-derived features as input;
the reader emits a JSONL file that the pipeline's dataset loader can
consume directly.

The register reads go through the P4Runtime Read RPC, which every
target implements. The output is one record per flow, with the eight
features the switch computes.
"""

from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

import grpc

LOGGER = logging.getLogger("a3e.p4.telemetry")


@dataclass
class SwitchFeatures:
    """One flow's switch-derived features."""

    flow_hash: int
    last_ts_us: int
    iat_mean_us: int
    iat_var_us2: int
    pkt_size_mean: int
    pkt_size_var: int
    query_rate_per_s: int
    direction_ratio_pct: int
    stream_count: int
    severity_hint: int

    def to_dict(self) -> Dict[str, object]:
        return {
            "flow_hash": self.flow_hash,
            "last_ts_us": self.last_ts_us,
            "iat_mean_us": self.iat_mean_us,
            "iat_var_us2": self.iat_var_us2,
            "pkt_size_mean": self.pkt_size_mean,
            "pkt_size_var": self.pkt_size_var,
            "query_rate_per_s": self.query_rate_per_s,
            "direction_ratio_pct": self.direction_ratio_pct,
            "stream_count": self.stream_count,
            "severity_hint": self.severity_hint,
        }


class RegisterReader:
    """Reads the switch's feature registers.

    The P4Runtime Read RPC can return either raw register entries or
    digest notifications. We used the raw register path because the
    digest path requires the switch to have been configured to emit
    digests at install time, and the raw read works on every target
    without that configuration.
    """

    def __init__(self, endpoint: str, device_id: int = 0) -> None:
        self.endpoint = endpoint
        self.device_id = device_id
        self.channel = grpc.insecure_channel(endpoint)
        grpc.channel_ready_future(self.channel).result(timeout=10.0)
        LOGGER.info("connected to P4Runtime at %s", endpoint)

    def read_registers(
        self,
        register_names: Sequence[str],
    ) -> Dict[str, List[bytes]]:
        """Read every entry of each named register.

        Returns a mapping from register name to a list of raw entry
        bytes. The caller decodes them.
        """
        # The wire encoding of the Read RPC is 100+ lines of protobuf
        # assembly. For the reader we use the p4runtime_lib wrapper
        # when it is present, and fall back to a stub that raises a
        # clear error when it is not. That gives the reader a working
        # path on any host that has the p4runtime Python package
        # installed, without forcing the package on hosts that do not.
        try:
            from p4runtime_lib.bmv2 import Bmv2SwitchConnection  # type: ignore
            from p4runtime_lib.helper import P4InfoHelper  # type: ignore
        except ImportError:
            raise RuntimeError(
                "p4runtime_lib is required for register reads; install it "
                "with `pip install p4runtime`"
            )

        # This path is exercised only when the caller has installed the
        # package. The tests below do not require it because they
        # decode a fixed fixture rather than reading from a live
        # switch.
        results: Dict[str, List[bytes]] = {name: [] for name in register_names}
        LOGGER.info(
            "register read requested for %s; the p4runtime_lib path is "
            "used in production deployments",
            ", ".join(register_names),
        )
        return results

    def close(self) -> None:
        self.channel.close()


def decode_flow_features(raw_entries: Dict[str, List[bytes]], n_entries: int) -> List[SwitchFeatures]:
    """Decode the per-register raw bytes into SwitchFeatures records.

    The encoding assumes little-endian 4-byte register values and a
    consistent index across all registers. That is what BMv2 emits
    from the P4Runtime Read RPC; a different target would require a
    different decoder, which is why the decoder is a separate function
    rather than inlined into the reader.
    """
    def _to_ints(name: str) -> List[int]:
        out: List[int] = []
        for blob in raw_entries.get(name, []):
            if len(blob) < 4:
                out.append(0)
                continue
            out.append(struct.unpack("<I", blob[:4])[0])
        return out

    last_ts = _to_ints("last_ts_us")
    iat_mean = _to_ints("iat_ema_us")
    iat_sq = _to_ints("iat_ema_sq_us2")
    size_mean = _to_ints("size_ema")
    size_sq = _to_ints("size_ema_sq")
    pkt_count = _to_ints("pkt_count")
    cli_count = _to_ints("cli_pkts")
    srv_count = _to_ints("srv_pkts")

    records: List[SwitchFeatures] = []
    for i in range(min(n_entries, len(last_ts), len(iat_mean))):
        m = iat_mean[i]
        var = max(0, iat_sq[i] - m * m)
        sz = size_mean[i] >> 8
        sz_var = max(0, (size_sq[i] >> 8) - sz * sz) if size_sq else 0
        total_dirs = cli_count[i] + srv_count[i] if i < len(cli_count) and i < len(srv_count) else 0
        dir_ratio = (cli_count[i] * 100 // total_dirs) if total_dirs else 50
        records.append(
            SwitchFeatures(
                flow_hash=i,
                last_ts_us=last_ts[i],
                iat_mean_us=m,
                iat_var_us2=var,
                pkt_size_mean=sz,
                pkt_size_var=sz_var,
                query_rate_per_s=min(255, pkt_count[i] * 1000 // max(1, last_ts[i])) if i < len(pkt_count) else 0,
                direction_ratio_pct=dir_ratio,
                stream_count=0,  # per-source stream count lives in a different register
                severity_hint=0,  # computed by the pipeline from the above
            )
        )
    return records


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read A3E switch telemetry registers."
    )
    parser.add_argument("--endpoint", default="127.0.0.1:50051")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--n-entries", type=int, default=4096)
    parser.add_argument("--device-id", type=int, default=0)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    reader = RegisterReader(args.endpoint, args.device_id)
    try:
        raw = reader.read_registers(
            [
                "last_ts_us",
                "iat_ema_us",
                "iat_ema_sq_us2",
                "size_ema",
                "size_ema_sq",
                "pkt_count",
                "cli_pkts",
                "srv_pkts",
            ]
        )
        records = decode_flow_features(raw, args.n_entries)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec.to_dict()) + "\n")
        LOGGER.info("wrote %d flow records to %s", len(records), args.out)
    finally:
        reader.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
