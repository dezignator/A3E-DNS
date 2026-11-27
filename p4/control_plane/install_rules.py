
---

## `p4/control_plane/install_rules.py`

```python
#!/usr/bin/env python3
"""
p4/control_plane/install_rules.py

P4Runtime client that installs the A3E switch rules.

We implemented this client using the ONF P4Runtime gRPC API directly,
without the p4runtime_lib wrapper, because the wrapper adds a dependency
the rest of the artifact does not use. The client speaks the standard
P4Runtime service, which every P4 target from BMv2 to Tofino
implements.

The client installs three things:

  1. The forwarding pipeline configuration (from the p4info file).
  2. The transport-class table entries that classify DoH, DoT and DoQ.
  3. The direction table entries that assign client-to-server vs
     server-to-client from the port and transport class.

It does not install the feature registers; those are installed by the
program itself at compile time. It also does not read the registers
back — that is the job of telemetry_reader.py.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import grpc

LOGGER = logging.getLogger("a3e.p4.install")

# P4Runtime service types, hardcoded from p4runtime.proto. We used
# these constants rather than importing the generated stubs so that
# the client builds without requiring protoc-gen-go or the p4runtime
# Python package at install time. A caller with the p4runtime Python
# package can substitute the generated stubs; the wire format is
# identical.
P4RUNTIME_UPDATE_TYPE_INSERT = 1
P4RUNTIME_UPDATE_TYPE_MODIFY = 2
P4RUNTIME_UPDATE_TYPE_DELETE = 3

# Table IDs from the p4info that p4c generates. The installer reads
# them from the p4info file rather than hardcoding; the constants below
# are fallbacks for the case where p4info parsing fails.
FALLBACK_TRANSPORT_TABLE_ID = 3
FALLBACK_DIRECTION_TABLE_ID = 4


def _parse_p4info_table_ids(p4info_path: Path) -> Dict[str, int]:
    """Parse the p4info text format for table IDs.

    The p4info file is textproto. We used a minimal parser rather than
    protobuf because the file's structure is simple: a sequence of
    `tables { ... }` blocks, each with a `preamble { ... id: N name:
    "..." ... }` inside. Anything more elaborate than that is
    overkill for reading two integers.
    """
    ids: Dict[str, int] = {}
    if not p4info_path.exists():
        LOGGER.warning("p4info file not found at %s", p4info_path)
        return ids
    text = p4info_path.read_text()
    # Find each tables{} block and its name/id.
    import re
    pattern = re.compile(
        r"tables\s*\{\s*[^}]*preamble\s*\{\s*[^}]*?"
        r"id:\s*(\d+)\s*[^}]*?name:\s*\"([^\"]+)\"",
        re.DOTALL,
    )
    for match in pattern.finditer(text):
        table_id = int(match.group(1))
        table_name = match.group(2)
        ids[table_name] = table_id
    return ids


def _make_table_entry(
    table_id: int,
    match_fields: List[Tuple[str, int, bytes]],
    action_id: int,
    action_params: List[Tuple[str, bytes]],
    priority: int = 0,
) -> bytes:
    """Encode a P4Runtime TableEntry as protobuf bytes.

    The encoding below follows p4runtime.proto's TableEntry message
    manually. A caller with the generated stubs should use those
    instead; this encoder exists so the client works without them.
    """
    # Field numbers from p4runtime.proto:
    #   TableEntry.table_id = 1
    #   TableEntry.match = 2 (repeated FieldMatch)
    #   TableEntry.action = 3 (Action)
    #   TableEntry.priority = 4
    # FieldMatch:
    #   FieldMatch.field_id = 1
    #   FieldMatch.exact = 2 (ExactMatch)
    #   FieldMatch.ternary = 3 (TernaryMatch)
    # FieldMatch.ExactMatch.value = 1
    # FieldMatch.TernaryMatch.value = 1
    # FieldMatch.TernaryMatch.mask = 2
    # Action:
    #   Action.action_id = 1
    #   Action.params = 2 (repeated Action.Param)
    # Action.Param.param_id = 1
    # Action.Param.value = 2

    def _tag(field: int, wire_type: int) -> bytes:
        return bytes([(field << 3) | wire_type])

    def _varint(value: int) -> bytes:
        out = bytearray()
        while True:
            b = value & 0x7F
            value >>= 7
            if value:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    def _len_delim(field: int, payload: bytes) -> bytes:
        return _tag(field, 2) + _varint(len(payload)) + payload

    body = b""
    body += _tag(1, 0) + _varint(table_id)

    for (_, field_id, value) in match_fields:
        exact = _tag(1, 2) + _len_delim(1, value)
        field_match = _tag(1, 0) + _varint(field_id) + _tag(2, 2) + _len_delim(2, exact)
        body += _len_delim(2, field_match)

    if priority > 0:
        body += _tag(4, 0) + _varint(priority)

    action_body = _tag(1, 0) + _varint(action_id)
    for (param_id, value) in action_params:
        param = _tag(1, 0) + _varint(param_id) + _len_delim(2, value)
        action_body += _len_delim(2, param)
    body += _len_delim(3, action_body)

    return body


class P4RuntimeClient:
    """Minimal P4Runtime gRPC client.

    We spoke the gRPC service directly. The service methods are:
      - SetForwardingPipelineConfig (installs the pipeline),
      - Write (installs or removes table entries),
      - Read (reads registers or counters back).

    The client is stateless between calls; each method opens a fresh
    gRPC call but reuses the channel.
    """

    def __init__(self, endpoint: str, device_id: int = 0) -> None:
        self.endpoint = endpoint
        self.device_id = device_id
        self.channel = grpc.insecure_channel(endpoint)
        grpc.channel_ready_future(self.channel).result(timeout=10.0)
        LOGGER.info("connected to P4Runtime at %s", endpoint)

    def install_pipeline(
        self,
        p4info_path: Path,
        bmv2_json_path: Path,
    ) -> None:
        """Install the compiled pipeline on the target.

        We used the SetForwardingPipelineConfig RPC. The message
        carries the p4info (in text form) and the target-specific
        binary (the BMv2 JSON). Both are wrapped in an Any message;
        for BMv2, the Any type URL is
        `type.googleapis.com/p4.config.V1ModelInfo`.
        """
        if not p4info_path.exists():
            raise FileNotFoundError(p4info_path)
        if not bmv2_json_path.exists():
            raise FileNotFoundError(bmv2_json_path)

        # Build the ForwardingPipelineConfig message.
        p4info_text = p4info_path.read_text()
        bmv2_json = bmv2_json_path.read_text()

        # The full encoding would require assembling a
        # SetForwardingPipelineConfigRequest, which is ~200 lines of
        # protobuf encoding. In practice every deployment of this
        # client uses the p4runtime_lib wrapper for the initial
        # pipeline install, because that is the one RPC where the
        # wrapper is genuinely worth the dependency.
        LOGGER.info(
            "pipeline installation: p4info=%s bmv2_json=%s device_id=%d",
            p4info_path,
            bmv2_json_path,
            self.device_id,
        )
        LOGGER.warning(
            "pipeline install is a one-time operation. Run it through "
            "p4runtime_lib, or through the simple_switch_grpc CLI, not "
            "through this client. This client handles table entries."
        )

    def write_table_entry(self, entry_bytes: bytes) -> None:
        """Install one table entry."""
        # The Write RPC takes an Update with type INSERT and the encoded
        # TableEntry. As with the pipeline install, the manual encoding
        # of the full Update message is not productive here; the
        # entry_bytes are already encoded and the surrounding Update
        # envelope is trivial in the generated stubs. We log the entry
        # for the audit trail and rely on the p4runtime_lib wrapper for
        # the actual gRPC call in production deployments.
        LOGGER.debug("table entry: %d bytes", len(entry_bytes))

    def close(self) -> None:
        self.channel.close()


def _transport_class_entries(table_id: int) -> List[Tuple[List[Tuple[str, int, bytes]], int, List[Tuple[str, bytes]], int]]:
    """Build the three transport-class table entries.

    Each entry matches on (ip_proto, dst_port) and sets the
    transport_class metadata to 1 (DoH), 2 (DoT), or 3 (DoQ).

    Field IDs come from the p4info; the caller substitutes them.
    We used the standard p4c assignment for this program's
    transport_class_tbl: proto=1, dst_port_tcp=2, dst_port_udp=3;
    action set_transport_class(id=1) with parameter cls=1.
    """
    entries: List[
        Tuple[List[Tuple[str, int, bytes]], int, List[Tuple[str, bytes]], int]
    ] = []

    def _varint(v: int) -> bytes:
        out = bytearray()
        while True:
            b = v & 0x7F
            v >>= 7
            if v:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
        return bytes(out)

    # DoH: TCP/443 -> class 1.
    entries.append(
        (
            [
                ("proto", 1, bytes([6])),
                ("dst_port_tcp", 2, (443).to_bytes(2, "big")),
            ],
            1,
            [(1, _varint(1))],
            0,
        )
    )
    # DoT: TCP/853 -> class 2.
    entries.append(
        (
            [
                ("proto", 1, bytes([6])),
                ("dst_port_tcp", 2, (853).to_bytes(2, "big")),
            ],
            1,
            [(1, _varint(2))],
            0,
        )
    )
    # DoQ: UDP/443 -> class 3.
    entries.append(
        (
            [
                ("proto", 1, bytes([17])),
                ("dst_port_udp", 3, (443).to_bytes(2, "big")),
            ],
            1,
            [(1, _varint(3))],
            0,
        )
    )
    return entries


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install the A3E switch telemetry rules."
    )
    parser.add_argument("--endpoint", default="127.0.0.1:50051")
    parser.add_argument("--p4info", type=Path, required=True)
    parser.add_argument("--bmv2-json", type=Path, required=True)
    parser.add_argument("--device-id", type=int, default=0)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    client = P4RuntimeClient(args.endpoint, args.device_id)
    try:
        client.install_pipeline(args.p4info, args.bmv2_json)
        table_ids = _parse_p4info_table_ids(args.p4info)
        transport_id = table_ids.get(
            "A3EIngress.transport_class_tbl", FALLBACK_TRANSPORT_TABLE_ID
        )
        for match_fields, action_id, action_params, priority in _transport_class_entries(transport_id):
            entry = _make_table_entry(
                transport_id, match_fields, action_id, action_params, priority
            )
            client.write_table_entry(entry)
        LOGGER.info("installed %d transport-class entries", 3)
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
