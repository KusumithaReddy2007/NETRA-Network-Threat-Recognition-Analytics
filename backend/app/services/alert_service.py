from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any


def get_severity(
    threat_class: str,
    confidence: float,
) -> str:
    """
    Map NETRA confidence + threat class to SOC severity.
    """

    if threat_class == "BENIGN":
        return "INFO"

    if threat_class in {"DDOS", "DOS"}:
        if confidence >= 90:
            return "CRITICAL"
        return "HIGH"

    if threat_class == "PORTSCAN":
        if confidence >= 90:
            return "HIGH"
        return "MEDIUM"

    if threat_class in {
        "BOT",
        "BOT_C2",
        "BRUTE_FORCE",
    }:
        return "HIGH"

    if threat_class in {
        "DNS_TUNNEL",
        "DGA",
    }:
        if confidence >= 90:
            return "HIGH"

        if confidence >= 70:
            return "MEDIUM"

        return "LOW"

    if threat_class == "EXFILTRATION":
        if confidence >= 90:
            return "CRITICAL"

        if confidence >= 70:
            return "HIGH"

        return "MEDIUM"

    if threat_class == "TLS_ANOMALY":
        if confidence >= 90:
            return "HIGH"

        if confidence >= 70:
            return "MEDIUM"

        return "LOW"

    if threat_class == "WEB_ATTACK":
        return "MEDIUM"

    return "LOW"


def get_supporting_evidence(
    flow_data: dict[str, Any],
    threat_class: str,
) -> dict[str, Any]:

    if threat_class in {"DDOS", "DOS"}:
        return {
            "flow_packets_per_s": flow_data.get(
                "Flow Packets/s"
            ),
            "flow_bytes_per_s": flow_data.get(
                "Flow Bytes/s"
            ),
            "syn_flag_count": flow_data.get(
                "SYN Flag Count"
            ),
            "total_fwd_packets": flow_data.get(
                "Total Fwd Packets"
            ),
        }

    if threat_class == "PORTSCAN":
        return {
            "destination_port": flow_data.get(
                "Destination Port"
            ),
            "flow_duration": flow_data.get(
                "Flow Duration"
            ),
            "total_fwd_packets": flow_data.get(
                "Total Fwd Packets"
            ),
            "syn_flag_count": flow_data.get(
                "SYN Flag Count"
            ),
        }

    if threat_class in {"BOT", "BOT_C2"}:
        return {
            "flow_iat_mean": flow_data.get(
                "Flow IAT Mean"
            ),
            "flow_iat_std": flow_data.get(
                "Flow IAT Std"
            ),
            "idle_mean": flow_data.get(
                "Idle Mean"
            ),
        }

    if threat_class == "BRUTE_FORCE":
        return {
            "destination_port": flow_data.get(
                "Destination Port"
            ),
            "flow_packets_per_s": flow_data.get(
                "Flow Packets/s"
            ),
            "total_fwd_packets": flow_data.get(
                "Total Fwd Packets"
            ),
        }

    if threat_class == "WEB_ATTACK":
        return {
            "destination_port": flow_data.get(
                "Destination Port"
            ),
            "packet_length_mean": flow_data.get(
                "Packet Length Mean"
            ),
            "flow_bytes_per_s": flow_data.get(
                "Flow Bytes/s"
            ),
        }

    if threat_class == "DNS_TUNNEL":
        return {
            "source_ip": flow_data.get(
                "source_ip"
            ),
            "query": flow_data.get(
                "query"
            ),
            "query_count": flow_data.get(
                "query_count"
            ),
            "query_rate_per_second": flow_data.get(
                "query_rate_per_second"
            ),
            "long_query_count": flow_data.get(
                "long_query_count"
            ),
            "long_query_ratio": flow_data.get(
                "long_query_ratio"
            ),
            "average_query_length": flow_data.get(
                "average_query_length"
            ),
            "average_entropy": flow_data.get(
                "average_entropy"
            ),
            "unique_query_ratio": flow_data.get(
                "unique_query_ratio"
            ),
            "supporting_signal_count": flow_data.get(
                "supporting_signal_count"
            ),
        }

    if threat_class == "DGA":
        return {
            "source_ip": flow_data.get(
                "source_ip"
            ),
            "query": flow_data.get(
                "query"
            ),
            "query_length": flow_data.get(
                "query_length"
            ),
            "longest_label_length": flow_data.get(
                "longest_label_length"
            ),
            "entropy": flow_data.get(
                "entropy"
            ),
            "max_label_entropy": flow_data.get(
                "max_label_entropy"
            ),
            "digit_ratio": flow_data.get(
                "digit_ratio"
            ),
            "vowel_ratio": flow_data.get(
                "vowel_ratio"
            ),
        }

    if threat_class == "EXFILTRATION":
        return {
            "outbound_bytes": flow_data.get(
                "outbound_bytes"
            ),
            "inbound_bytes": flow_data.get(
                "inbound_bytes"
            ),
            "outbound_inbound_ratio": flow_data.get(
                "outbound_inbound_ratio"
            ),
        }

    if threat_class == "TLS_ANOMALY":
        return {
            "source_ip": flow_data.get(
                "source_ip"
            ),
            "destination_ip": flow_data.get(
                "destination_ip"
            ),
            "destination_port": flow_data.get(
                "destination_port"
            ),
            "tls_version": flow_data.get(
                "tls_version"
            ),
            "cipher": flow_data.get(
                "cipher"
            ),
            "server_name": flow_data.get(
                "server_name"
            ),
            "ja4": flow_data.get(
                "ja4"
            ),
            "ja4s": flow_data.get(
                "ja4s"
            ),
            "unique_ja4_count": flow_data.get(
                "unique_ja4_count"
            ),
            "unique_ja4s_count": flow_data.get(
                "unique_ja4s_count"
            ),
            "event_rate_per_second": flow_data.get(
                "event_rate_per_second"
            ),
            "periodicity_cv": flow_data.get(
                "periodicity_cv"
            ),
            "anomaly_signals": flow_data.get(
                "anomaly_signals"
            ),
            "supporting_signal_count": flow_data.get(
                "supporting_signal_count"
            ),
            "payload_decryption": False,
        }

    return {
        "flow_packets_per_s": flow_data.get(
            "Flow Packets/s"
        ),
        "average_packet_size": flow_data.get(
            "Average Packet Size"
        ),
    }


def create_alert(
    flow_data: dict[str, Any],
    ml_analysis: dict[str, Any],
    *,
    flow_id: str | None = None,
    timestamp: str | None = None,
    supporting_evidence: dict[str, Any] | None = None,
):
    """
    Create the common NETRA alert schema.
    """

    threat_class = str(
        ml_analysis["threat_class"]
    )

    confidence = float(
        ml_analysis["confidence"]
    )

    severity = get_severity(
        threat_class,
        confidence,
    )

    evidence = (
        supporting_evidence
        if supporting_evidence is not None
        else get_supporting_evidence(
            flow_data,
            threat_class,
        )
    )

    alert_flow_id = (
        flow_id
        if flow_id
        else f"FLOW-{uuid.uuid4().hex[:12].upper()}"
    )

    alert_timestamp = (
        timestamp
        if timestamp
        else datetime.now(
            timezone.utc
        ).isoformat()
    )

    return {
        "alert_id": (
            f"NETRA-{uuid.uuid4().hex[:12].upper()}"
        ),
        "timestamp": alert_timestamp,
        "flow_id": alert_flow_id,
        "threat_class": threat_class,
        "severity": severity,
        "confidence": confidence,
        "supporting_evidence": evidence,
    }


def create_behavioral_alert(
    *,
    flow_id: str,
    timestamp: str,
    threat_class: str,
    confidence: float,
    supporting_evidence: dict[str, Any],
):
    """
    Create a standardized NETRA alert directly from a
    behavioral detector such as DNS, DDoS, scanning,
    C2, exfiltration, or TLS.
    """

    return create_alert(
        flow_data={},
        ml_analysis={
            "threat_class": threat_class,
            "confidence": confidence,
        },
        flow_id=flow_id,
        timestamp=timestamp,
        supporting_evidence=supporting_evidence,
    )
