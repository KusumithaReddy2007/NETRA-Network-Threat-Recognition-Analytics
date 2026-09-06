from __future__ import annotations

import math
from collections import Counter
from typing import Any

from .flow_normalizer import NetraFlow


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0

    return numerator / denominator


def shannon_entropy(value: str) -> float:
    """
    Shannon entropy for DNS/DGA-style string analysis.

    This operates on observable metadata only.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_flow_features(flow: NetraFlow) -> dict[str, Any]:
    total_bytes = flow.orig_bytes + flow.resp_bytes
    total_packets = flow.orig_pkts + flow.resp_pkts

    bytes_per_second = (
        safe_ratio(total_bytes, flow.duration)
        if flow.duration > 0
        else 0.0
    )

    packets_per_second = (
        safe_ratio(total_packets, flow.duration)
        if flow.duration > 0
        else 0.0
    )

    outbound_inbound_ratio = safe_ratio(
        flow.orig_bytes,
        flow.resp_bytes,
    )

    packet_ratio = safe_ratio(
        flow.orig_pkts,
        flow.resp_pkts,
    )

    average_packet_size = safe_ratio(
        total_bytes,
        total_packets,
    )

    return {
        "timestamp": flow.timestamp,
        "flow_id": flow.flow_id,

        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,

        "protocol": flow.protocol,
        "service": flow.service,

        "duration": flow.duration,

        "orig_bytes": flow.orig_bytes,
        "resp_bytes": flow.resp_bytes,

        "orig_pkts": flow.orig_pkts,
        "resp_pkts": flow.resp_pkts,

        "total_bytes": total_bytes,
        "total_packets": total_packets,

        "bytes_per_second": bytes_per_second,
        "packets_per_second": packets_per_second,

        "outbound_inbound_ratio": outbound_inbound_ratio,
        "packet_ratio": packet_ratio,

        "average_packet_size": average_packet_size,

        "conn_state": flow.conn_state,
        "history": flow.history,
    }
