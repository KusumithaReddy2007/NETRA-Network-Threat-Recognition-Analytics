from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from .zeek_reader import ZeekRecord


def _to_float(value: str | None) -> float:
    if value in (None, ""):
        return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _to_int(value: str | None) -> int:
    if value in (None, ""):
        return 0

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


@dataclass
class NetraFlow:
    """
    Canonical flow representation used by NETRA.

    This schema intentionally keeps source/destination metadata because
    the SIH problem requires behavioral analysis such as:
      - DDoS source concentration
      - port-scan fan-out
      - C2 periodicity
      - outbound/inbound asymmetry
    """

    timestamp: float
    flow_id: str

    src_ip: str
    src_port: int

    dst_ip: str
    dst_port: int

    protocol: str
    service: str

    duration: float

    orig_bytes: int
    resp_bytes: int

    orig_pkts: int
    resp_pkts: int

    conn_state: str

    history: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _stable_flow_id(record: dict[str, str]) -> str:
    """
    Prefer Zeek's connection UID.

    Fall back to a deterministic hash if UID is unavailable.
    """

    uid = record.get("uid", "").strip()

    if uid:
        return uid

    material = "|".join(
        [
            record.get("ts", ""),
            record.get("id.orig_h", ""),
            record.get("id.orig_p", ""),
            record.get("id.resp_h", ""),
            record.get("id.resp_p", ""),
            record.get("proto", ""),
        ]
    )

    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def normalize_connection(record: ZeekRecord) -> NetraFlow:
    fields = record.fields

    return NetraFlow(
        timestamp=_to_float(fields.get("ts")),
        flow_id=_stable_flow_id(fields),

        src_ip=fields.get("id.orig_h", ""),
        src_port=_to_int(fields.get("id.orig_p")),

        dst_ip=fields.get("id.resp_h", ""),
        dst_port=_to_int(fields.get("id.resp_p")),

        protocol=fields.get("proto", "").lower(),
        service=fields.get("service", "").lower(),

        duration=_to_float(fields.get("duration")),

        orig_bytes=_to_int(fields.get("orig_bytes")),
        resp_bytes=_to_int(fields.get("resp_bytes")),

        orig_pkts=_to_int(fields.get("orig_pkts")),
        resp_pkts=_to_int(fields.get("resp_pkts")),

        conn_state=fields.get("conn_state", ""),
        history=fields.get("history", ""),
    )
