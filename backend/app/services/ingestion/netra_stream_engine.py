from __future__ import annotations

from time import perf_counter
from typing import Any

from app.services.alert_service import (
    create_behavioral_alert,
)
from app.services.dns.dns_detector import (
    DNSBehaviorEngine,
)
from app.services.dns.dns_reader import (
    ZeekDNSRecord,
)
from app.services.ingestion.flow_normalizer import (
    NetraFlow,
)
from app.services.ingestion.stream_processor import (
    StreamingDetectionEngine,
)
from app.services.tls.tls_correlator import (
    TLSConnectionProfile,
    build_tls_connection_profile,
)
from app.services.tls.tls_detector import (
    TLSBehaviorEngine,
)
from app.services.tls.tls_c2_beacon import (
    TLSC2BeaconEngine,
)
from app.services.tls.tls_reader import (
    ZeekTLSRecord,
)
from app.services.quic.quic_reader import (
    ZeekQUICRecord,
)
from app.services.quic.quic_detector import (
    QUICMetadataDetector,
)


class NetraStreamEngine:
    """
    Unified NETRA streaming detection engine.

    Handles:
      - IP flow behavioral detection
      - DNS behavioral detection
      - TLS metadata + JA4/JA4S detection
      - standardized NETRA alert generation

    TLS payloads are never decrypted.
    """

    def __init__(
        self,
        flow_window_seconds: float = 10.0,
        dns_window_seconds: float = 60.0,
        tls_window_seconds: float = 60.0,
    ) -> None:

        self.flow_engine = StreamingDetectionEngine(
            window_seconds=flow_window_seconds,
        )

        self.dns_engine = DNSBehaviorEngine(
            window_seconds=dns_window_seconds,
        )

        self.tls_engine = TLSBehaviorEngine(
            window_seconds=tls_window_seconds,
        )

        self.tls_c2_engine = TLSC2BeaconEngine(
            window_seconds=180.0,
            minimum_events=4,
            max_cv=0.20,
            min_interval=5.0,
            max_interval=60.0,
        )

        self.quic_engine = QUICMetadataDetector(
            score_threshold=60.0,
        )

    def process_flow(
        self,
        flow: NetraFlow,
    ) -> dict[str, Any]:

        return self.flow_engine.process_flow(flow)

    def process_dns(
        self,
        record: ZeekDNSRecord,
    ) -> dict[str, Any]:

        start = perf_counter()

        fields = record.fields

        detections = self.dns_engine.analyze(
            record
        )

        triggered_detections = [
            detection
            for detection in detections
            if detection.triggered
        ]

        tunnel_triggered = any(
            detection.threat_class == "DNS_TUNNEL"
            for detection in triggered_detections
        )

        if tunnel_triggered:
            triggered_detections = [
                detection
                for detection in triggered_detections
                if detection.threat_class != "DGA"
            ]

        triggered = [
            {
                "detector": detection.detector,
                "threat_class": detection.threat_class,
                "score": detection.score,
                "evidence": detection.evidence,
            }
            for detection in triggered_detections
        ]

        alerts = []

        zeek_uid = str(
            fields.get("uid", "") or ""
        ).strip()

        flow_id = (
            f"DNS-{zeek_uid}"
            if zeek_uid
            else (
                f"DNS-"
                f"{fields.get('id.orig_h', 'unknown')}-"
                f"{fields.get('query', 'unknown')}"
            )
        )

        timestamp = str(
            fields.get("ts", "") or ""
        )

        for detection in triggered_detections:

            alert = create_behavioral_alert(
                flow_id=flow_id,
                timestamp=timestamp,
                threat_class=detection.threat_class,
                confidence=float(
                    detection.score
                ),
                supporting_evidence=detection.evidence,
            )

            alerts.append(alert)

        elapsed_ms = (
            perf_counter() - start
        ) * 1000

        return {
            "event_type": "dns",
            "flow_id": fields.get(
                "uid",
                "",
            ),
            "timestamp": fields.get(
                "ts",
                "",
            ),
            "source_ip": fields.get(
                "id.orig_h",
                "",
            ),
            "destination_ip": fields.get(
                "id.resp_h",
                "",
            ),
            "query": fields.get(
                "query",
                "",
            ),
            "behavioral_detections": triggered,
            "alerts": alerts,
            "processing_latency_ms": round(
                elapsed_ms,
                3,
            ),
        }

    def process_tls(
        self,
        record: ZeekTLSRecord,
        conn_fields: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Process one Zeek TLS record.

        TLS metadata is analyzed without decrypting payloads.

        Two complementary metadata-only detectors are used:
          - TLSBehaviorEngine: generic TLS anomaly detection
          - TLSC2BeaconEngine: encrypted C2 beacon behavior

        When conn_fields are supplied, TLS and connection metadata
        are correlated by Zeek UID.
        """

        start = perf_counter()

        if conn_fields is None:
            conn_fields = {}

        fields = record.fields

        # Run the existing generic TLS anomaly detector.
        anomaly_detection = self.tls_engine.analyze(record)

        # Run the encrypted-C2 beacon detector.
        c2_detection = self.tls_c2_engine.analyze(fields)

        detections = [
            anomaly_detection,
            c2_detection,
        ]

        # Build correlated connection profile.
        profile = build_tls_connection_profile(
            fields,
            conn_fields,
        )

        uid = str(
            fields.get("uid", "")
            or profile.uid
            or ""
        ).strip()

        flow_id = (
            f"TLS-{uid}"
            if uid
            else "TLS-UNKNOWN"
        )

        timestamp = str(
            fields.get("ts", "")
            or profile.timestamp
        )

        behavioral_detections = []
        alerts = []

        for detection in detections:

            evidence = dict(
                detection.evidence
            )

            # Add correlated flow metadata.
            evidence.update(
                {
                    "destination_ip": profile.destination_ip,
                    "source_port": profile.source_port,
                    "destination_port": profile.destination_port,
                    "duration_seconds": profile.duration,
                    "orig_bytes": profile.orig_bytes,
                    "resp_bytes": profile.resp_bytes,
                    "orig_packets": profile.orig_packets,
                    "resp_packets": profile.resp_packets,
                    "packet_count": profile.packet_count,
                    "packet_rate": profile.packet_rate,
                    "byte_rate": profile.byte_rate,
                    "outbound_inbound_byte_ratio": (
                        profile.outbound_inbound_byte_ratio
                    ),
                    "service": profile.service,
                    "conn_state": profile.conn_state,
                    "conn_history": profile.conn_history,
                    "ja4": profile.ja4,
                    "ja4s": profile.ja4s,
                    "payload_decryption": False,
                }
            )

            behavioral_detections.append(
                {
                    "detector": detection.detector,
                    "threat_class": detection.threat_class,
                    "score": detection.score,
                    "triggered": detection.triggered,
                    "evidence": evidence,
                }
            )

            if detection.triggered:
                alerts.append(
                    create_behavioral_alert(
                        flow_id=flow_id,
                        timestamp=timestamp,
                        threat_class=detection.threat_class,
                        confidence=float(
                            detection.score
                        ),
                        supporting_evidence=evidence,
                    )
                )

        elapsed_ms = (
            perf_counter() - start
        ) * 1000

        return {
            "event_type": "tls",
            "flow_id": fields.get(
                "uid",
                profile.uid,
            ),
            "timestamp": fields.get(
                "ts",
                profile.timestamp,
            ),
            "source_ip": fields.get(
                "id.orig_h",
                profile.source_ip,
            ),
            "destination_ip": fields.get(
                "id.resp_h",
                profile.destination_ip,
            ),
            "ja4": profile.ja4,
            "ja4s": profile.ja4s,
            "behavioral_detections": behavioral_detections,
            "alerts": alerts,
            "profile": {
                "uid": profile.uid,
                "source_ip": profile.source_ip,
                "destination_ip": profile.destination_ip,
                "source_port": profile.source_port,
                "destination_port": profile.destination_port,
                "tls_version": profile.tls_version,
                "cipher": profile.cipher,
                "curve": profile.curve,
                "server_name": profile.server_name,
                "ja4": profile.ja4,
                "ja4s": profile.ja4s,
                "duration": profile.duration,
                "orig_bytes": profile.orig_bytes,
                "resp_bytes": profile.resp_bytes,
                "orig_packets": profile.orig_packets,
                "resp_packets": profile.resp_packets,
                "packet_rate": profile.packet_rate,
                "byte_rate": profile.byte_rate,
                "outbound_inbound_byte_ratio": (
                    profile.outbound_inbound_byte_ratio
                ),
                "payload_decryption": False,
            },
            "processing_latency_ms": round(
                elapsed_ms,
                3,
            ),
        }


    def process_quic(
        self,
        record: ZeekQUICRecord,
    ) -> dict[str, Any]:
        """
        Process one Zeek QUIC metadata record.

        QUIC is analyzed strictly from metadata produced by Zeek.
        NETRA never decrypts or inspects the QUIC payload.
        """

        start = perf_counter()

        fields = record.fields

        detection = self.quic_engine.analyze(
            fields
        )

        flow_id = (
            f"QUIC-{fields.get('uid', '')}"
            if fields.get("uid")
            else (
                f"QUIC-"
                f"{fields.get('id.orig_h', 'unknown')}-"
                f"{fields.get('id.resp_h', 'unknown')}"
            )
        )

        timestamp = str(
            fields.get("ts", "") or ""
        )

        evidence = dict(
            detection.evidence
        )

        evidence.update(
            {
                "event_type": "quic",
                "uid": fields.get(
                    "uid",
                    "",
                ),
                "version": fields.get(
                    "version",
                    "",
                ),
                "client_initial_dcid": fields.get(
                    "client_initial_dcid",
                    "",
                ),
                "client_scid": fields.get(
                    "client_scid",
                    "",
                ),
                "server_scid": fields.get(
                    "server_scid",
                    "",
                ),
                "server_name": fields.get(
                    "server_name",
                    "",
                ),
                "client_protocol": fields.get(
                    "client_protocol",
                    "",
                ),
                "history": fields.get(
                    "history",
                    "",
                ),
                "payload_decryption": False,
            }
        )

        behavioral_detection = {
            "detector": detection.detector,
            "threat_class": detection.threat_class,
            "score": detection.score,
            "triggered": detection.triggered,
            "evidence": evidence,
        }

        alerts = []

        if detection.triggered:
            alerts.append(
                create_behavioral_alert(
                    flow_id=flow_id,
                    timestamp=timestamp,
                    threat_class=detection.threat_class,
                    confidence=float(
                        detection.score
                    ),
                    supporting_evidence=evidence,
                )
            )

        elapsed_ms = (
            perf_counter() - start
        ) * 1000

        return {
            "event_type": "quic",
            "flow_id": fields.get(
                "uid",
                "",
            ),
            "timestamp": fields.get(
                "ts",
                "",
            ),
            "source_ip": fields.get(
                "id.orig_h",
                "",
            ),
            "destination_ip": fields.get(
                "id.resp_h",
                "",
            ),
            "quic_version": fields.get(
                "version",
                "",
            ),
            "client_protocol": fields.get(
                "client_protocol",
                "",
            ),
            "server_name": fields.get(
                "server_name",
                "",
            ),
            "behavioral_detections": [
                behavioral_detection
            ],
            "alerts": alerts,
            "payload_decryption": False,
            "processing_latency_ms": round(
                elapsed_ms,
                3,
            ),
        }
