from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TLSConnectionProfile:
    uid: str
    timestamp: float
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    tls_version: str
    cipher: str
    curve: str
    server_name: str
    next_protocol: str
    ssl_history: str

    # JA4+ fingerprint metadata
    ja4: str
    ja4s: str

    duration: float
    orig_bytes: int
    resp_bytes: int
    orig_packets: int
    resp_packets: int

    outbound_inbound_byte_ratio: float
    packet_count: int
    packet_rate: float
    byte_rate: float

    sni_present: bool
    resumed: bool
    service: str
    conn_state: str
    conn_history: str


def _clean(value: object) -> str:
    if value is None:
        return ""

    value = str(value).strip()

    if value in {"-", "(empty)"}:
        return ""

    return value


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: object) -> bool:
    return str(value).strip().lower() in {
        "t",
        "true",
        "1",
        "yes",
    }


def _safe_ratio(
    numerator: float,
    denominator: float,
) -> float:
    return numerator / denominator if denominator else 0.0


def build_tls_connection_profile(
    tls_fields: dict[str, str],
    conn_fields: dict[str, str],
) -> TLSConnectionProfile:

    uid = _clean(
        tls_fields.get(
            "uid",
            "",
        )
        or conn_fields.get(
            "uid",
            "",
        )
    )

    timestamp = _to_float(
        conn_fields.get(
            "ts",
            tls_fields.get("ts", "0"),
        )
    )

    source_ip = _clean(
        conn_fields.get(
            "id.orig_h",
            tls_fields.get("id.orig_h", ""),
        )
    )

    source_port = _to_int(
        conn_fields.get(
            "id.orig_p",
            tls_fields.get("id.orig_p", "0"),
        )
    )

    destination_ip = _clean(
        conn_fields.get(
            "id.resp_h",
            tls_fields.get("id.resp_h", ""),
        )
    )

    destination_port = _to_int(
        conn_fields.get(
            "id.resp_p",
            tls_fields.get("id.resp_p", "0"),
        )
    )

    duration = _to_float(
        conn_fields.get(
            "duration",
            "0",
        )
    )

    orig_bytes = _to_int(
        conn_fields.get(
            "orig_bytes",
            "0",
        )
    )

    resp_bytes = _to_int(
        conn_fields.get(
            "resp_bytes",
            "0",
        )
    )

    orig_packets = _to_int(
        conn_fields.get(
            "orig_pkts",
            "0",
        )
    )

    resp_packets = _to_int(
        conn_fields.get(
            "resp_pkts",
            "0",
        )
    )

    packet_count = (
        orig_packets + resp_packets
    )

    total_bytes = (
        orig_bytes + resp_bytes
    )

    outbound_inbound_ratio = _safe_ratio(
        orig_bytes,
        resp_bytes,
    )

    packet_rate = (
        _safe_ratio(
            packet_count,
            duration,
        )
        if duration > 0
        else 0.0
    )

    byte_rate = (
        _safe_ratio(
            total_bytes,
            duration,
        )
        if duration > 0
        else 0.0
    )

    server_name = _clean(
        tls_fields.get(
            "server_name",
            "",
        )
    )

    return TLSConnectionProfile(
        uid=uid,
        timestamp=timestamp,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,

        tls_version=_clean(
            tls_fields.get(
                "version",
                "",
            )
        ),

        cipher=_clean(
            tls_fields.get(
                "cipher",
                "",
            )
        ),

        curve=_clean(
            tls_fields.get(
                "curve",
                "",
            )
        ),

        server_name=server_name,

        next_protocol=_clean(
            tls_fields.get(
                "next_protocol",
                "",
            )
        ),

        ssl_history=_clean(
            tls_fields.get(
                "ssl_history",
                "",
            )
        ),

        ja4=_clean(
            tls_fields.get(
                "ja4",
                "",
            )
        ),

        ja4s=_clean(
            tls_fields.get(
                "ja4s",
                "",
            )
        ),

        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_packets=orig_packets,
        resp_packets=resp_packets,

        outbound_inbound_byte_ratio=round(
            outbound_inbound_ratio,
            6,
        ),

        packet_count=packet_count,

        packet_rate=round(
            packet_rate,
            6,
        ),

        byte_rate=round(
            byte_rate,
            6,
        ),

        sni_present=bool(server_name),

        resumed=_to_bool(
            tls_fields.get(
                "resumed",
                "",
            )
        ),

        service=_clean(
            conn_fields.get(
                "service",
                "",
            )
        ),

        conn_state=_clean(
            conn_fields.get(
                "conn_state",
                "",
            )
        ),

        conn_history=_clean(
            conn_fields.get(
                "history",
                "",
            )
        ),
    )
