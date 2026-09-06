from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class QUICDetection:
    detector: str
    threat_class: str
    score: float
    triggered: bool
    evidence: dict[str, Any]


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class QUICMetadataDetector:
    """
    Passive QUIC metadata anomaly detector.

    This detector never inspects or decrypts QUIC payloads.
    It operates only on Zeek-generated metadata.
    """

    def __init__(
        self,
        suspicious_ports: set[int] | None = None,
        score_threshold: float = 60.0,
    ) -> None:
        self.suspicious_ports = suspicious_ports or {
            4433,
            8443,
            9443,
        }
        self.score_threshold = score_threshold

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    def analyze(
        self,
        record_fields: dict[str, str],
    ) -> QUICDetection:

        version = str(
            record_fields.get("version", "") or ""
        ).strip()

        server_name = str(
            record_fields.get("server_name", "") or ""
        ).strip()

        client_protocol = str(
            record_fields.get("client_protocol", "") or ""
        ).strip()

        history = str(
            record_fields.get("history", "") or ""
        ).strip()

        orig_port = _to_int(
            record_fields.get("id.orig_p"),
            0,
        )

        resp_port = _to_int(
            record_fields.get("id.resp_p"),
            0,
        )

        signals: list[str] = []

        # Non-standard destination ports can be useful metadata
        # for encrypted QUIC anomaly triage.
        unusual_port = (
            resp_port not in {443, 4430}
            or resp_port in self.suspicious_ports
        )

        if unusual_port:
            signals.append("unusual_destination_port")

        # A missing SNI is not inherently malicious, but is useful as
        # supporting evidence when combined with other anomalies.
        missing_sni = not server_name
        if missing_sni:
            signals.append("missing_server_name")

        # Unknown/non-standard QUIC versions are useful metadata
        # anomalies.
        unusual_version = (
            bool(version)
            and version.lower()
            not in {
                "1",
                "2",
                "quic",
                "quicv1",
                "quicv2",
            }
        )

        if unusual_version:
            signals.append("unusual_quic_version")

        # Non-HTTP/3 application protocol is only supporting evidence.
        unusual_application = (
            bool(client_protocol)
            and client_protocol.lower() not in {
                "h3",
                "h3-29",
                "h3-32",
                "hq",
            }
        )

        if unusual_application:
            signals.append("unusual_application_protocol")

        # A very short/empty handshake history gives us additional
        # metadata evidence, but is never sufficient alone.
        short_history = len(history) <= 3
        if short_history:
            signals.append("short_quic_history")

        signal_score = (
            0.25 * float(unusual_port)
            + 0.20 * float(missing_sni)
            + 0.25 * float(unusual_version)
            + 0.15 * float(unusual_application)
            + 0.15 * float(short_history)
        )

        score = round(signal_score * 100.0, 2)

        # Require multiple independent signals so that a normal
        # QUIC session with a missing SNI does not become an alert.
        triggered = (
            score >= self.score_threshold
            and len(signals) >= 2
        )

        return QUICDetection(
            detector="quic_metadata_anomaly",
            threat_class="QUIC_ANOMALY",
            score=score,
            triggered=triggered,
            evidence={
                "src_ip": record_fields.get(
                    "id.orig_h",
                    "",
                ),
                "src_port": orig_port,
                "dst_ip": record_fields.get(
                    "id.resp_h",
                    "",
                ),
                "dst_port": resp_port,
                "quic_version": version,
                "server_name": server_name or None,
                "client_protocol": client_protocol or None,
                "history": history,
                "supporting_signals": signals,
                "supporting_signal_count": len(signals),
                "payload_decryption": False,
            },
        )
