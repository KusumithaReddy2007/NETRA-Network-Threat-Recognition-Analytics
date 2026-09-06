from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from .tls_features import (
    TLSFeatures,
    extract_tls_features,
)
from .tls_reader import ZeekTLSRecord


@dataclass
class TLSDetection:
    detector: str
    threat_class: str
    score: float
    triggered: bool
    evidence: dict[str, Any]


class TLSBehaviorEngine:
    """
    Metadata-only TLS anomaly detector.

    No TLS payload is decrypted.

    JA4/JA4S are fingerprint metadata and are used as
    contextual evidence. A fingerprint alone never triggers
    an alert.

    Detection combines multiple independent metadata signals:
      - missing SNI
      - unusual destination port
      - incomplete TLS metadata
      - uncommon TLS version
      - burst rate
      - destination diversity
      - regularity/periodicity

    Thresholds are prototype starting points and must be
    validated against representative benign and malicious
    traffic before being treated as production thresholds.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        minimum_events: int = 3,
        score_threshold: float = 70.0,
        minimum_supporting_signals: int = 3,
    ) -> None:
        self.window_seconds = window_seconds
        self.minimum_events = minimum_events
        self.score_threshold = score_threshold
        self.minimum_supporting_signals = (
            minimum_supporting_signals
        )

        self.events: dict[
            str,
            deque[tuple[float, TLSFeatures, str]],
        ] = defaultdict(deque)

    def _expire(
        self,
        source: str,
        timestamp: float,
    ) -> None:
        cutoff = timestamp - self.window_seconds
        queue = self.events[source]

        while queue and queue[0][0] < cutoff:
            queue.popleft()

    @staticmethod
    def _safe_ratio(
        numerator: float,
        denominator: float,
    ) -> float:
        return (
            numerator / denominator
            if denominator
            else 0.0
        )

    @staticmethod
    def _coefficient_of_variation(
        timestamps: list[float],
    ) -> float:
        if len(timestamps) < 3:
            return 1.0

        timestamps = sorted(timestamps)

        intervals = [
            b - a
            for a, b in zip(
                timestamps,
                timestamps[1:],
            )
            if b > a
        ]

        if len(intervals) < 2:
            return 1.0

        average = mean(intervals)

        if average <= 0:
            return 1.0

        return pstdev(intervals) / average

    @staticmethod
    def _periodicity_signal(
        coefficient_of_variation: float,
    ) -> float:
        """
        Convert low inter-arrival variation into a signal.

        CV <= 0.05  -> very regular
        CV >= 0.50  -> no periodicity signal
        """

        if coefficient_of_variation <= 0.05:
            return 1.0

        if coefficient_of_variation >= 0.50:
            return 0.0

        return (
            0.50 - coefficient_of_variation
        ) / 0.45

    def analyze(
        self,
        record: ZeekTLSRecord,
    ) -> TLSDetection:

        fields = record.fields

        try:
            timestamp = float(
                fields.get(
                    "ts",
                    0.0,
                )
                or 0.0
            )
        except (TypeError, ValueError):
            timestamp = 0.0

        source = str(
            fields.get(
                "id.orig_h",
                "",
            )
            or "unknown"
        )

        destination = str(
            fields.get(
                "id.resp_h",
                "",
            )
            or ""
        )

        features = extract_tls_features(
            fields
        )

        queue = self.events[source]

        queue.append(
            (
                timestamp,
                features,
                destination,
            )
        )

        self._expire(
            source,
            timestamp,
        )

        events = [
            item
            for _, item, _ in queue
        ]

        timestamps = [
            ts
            for ts, _, _ in queue
        ]

        destinations = [
            dst
            for _, _, dst in queue
            if dst
        ]

        unique_destinations = set(
            destinations
        )

        unique_ja4 = {
            item.ja4
            for item in events
            if item.ja4
        }

        unique_ja4s = {
            item.ja4s
            for item in events
            if item.ja4s
        }

        missing_sni_count = sum(
            not item.has_sni
            for item in events
        )

        unusual_port_count = sum(
            item.unusual_port
            for item in events
        )

        incomplete_metadata_count = sum(
            item.handshake_anomaly
            for item in events
        )

        uncommon_version_count = sum(
            bool(item.version)
            and not (
                item.is_tls12
                or item.is_tls13
            )
            for item in events
        )

        missing_ja4_count = sum(
            not item.has_ja4
            for item in events
        )

        anomaly_signals: list[str] = []

        if not features.has_sni:
            anomaly_signals.append(
                "missing_sni"
            )

        if features.unusual_port:
            anomaly_signals.append(
                "unusual_destination_port"
            )

        if features.handshake_anomaly:
            anomaly_signals.append(
                "tls_metadata_incomplete"
            )

        if (
            features.version
            and not (
                features.is_tls12
                or features.is_tls13
            )
        ):
            anomaly_signals.append(
                "uncommon_tls_version"
            )

        if not features.cipher:
            anomaly_signals.append(
                "missing_cipher"
            )

        event_rate = self._safe_ratio(
            len(events),
            self.window_seconds,
        )

        regularity_cv = (
            self._coefficient_of_variation(
                timestamps
            )
            if len(timestamps) >= 4
            else None
        )

        periodicity_signal = (
            self._periodicity_signal(
                regularity_cv
            )
            if regularity_cv is not None
            else 0.0
        )

        # ---------------------------------------------------------
        # Normalized anomaly signals
        # ---------------------------------------------------------

        missing_sni_signal = self._safe_ratio(
            missing_sni_count,
            len(events),
        )

        unusual_port_signal = self._safe_ratio(
            unusual_port_count,
            len(events),
        )

        incomplete_signal = self._safe_ratio(
            incomplete_metadata_count,
            len(events),
        )

        uncommon_version_signal = self._safe_ratio(
            uncommon_version_count,
            len(events),
        )

        burst_signal = min(
            event_rate / 1.0,
            1.0,
        )

        destination_signal = min(
            len(unique_destinations) / 10.0,
            1.0,
        )

        # ---------------------------------------------------------
        # Weighted scoring
        #
        # Missing SNI + incomplete metadata + uncommon TLS
        # together provide strong evidence in the controlled
        # anomalous test.
        #
        # JA4 is intentionally NOT a standalone maliciousness
        # score.
        # ---------------------------------------------------------

        score = 100.0 * (
            0.25 * missing_sni_signal
            + 0.10 * unusual_port_signal
            + 0.30 * incomplete_signal
            + 0.20 * uncommon_version_signal
            + 0.10 * burst_signal
            + 0.03 * destination_signal
            + 0.02 * periodicity_signal
        )

        supporting_signals = sum(
            [
                missing_sni_signal >= 0.50,
                unusual_port_signal >= 0.50,
                incomplete_signal >= 0.50,
                uncommon_version_signal >= 0.50,
                burst_signal >= 0.50,
                periodicity_signal >= 0.80,
            ]
        )

        triggered = (
            len(events) >= self.minimum_events
            and score >= self.score_threshold
            and supporting_signals
            >= self.minimum_supporting_signals
        )

        return TLSDetection(
            detector="tls_metadata_anomaly",
            threat_class="TLS_ANOMALY",
            score=round(
                score,
                2,
            ),
            triggered=triggered,
            evidence={
                "source_ip": source,
                "window_seconds": (
                    self.window_seconds
                ),
                "event_count": len(events),

                "event_rate_per_second": round(
                    event_rate,
                    4,
                ),

                "unique_destination_count": len(
                    unique_destinations
                ),

                "missing_sni_count": (
                    missing_sni_count
                ),

                "unusual_port_count": (
                    unusual_port_count
                ),

                "incomplete_tls_metadata_count": (
                    incomplete_metadata_count
                ),

                "uncommon_tls_version_count": (
                    uncommon_version_count
                ),

                "missing_ja4_count": (
                    missing_ja4_count
                ),

                "tls_version": features.version,
                "cipher": features.cipher,
                "curve": features.curve,

                "server_name": (
                    features.server_name
                ),

                "server_name_present": (
                    features.has_sni
                ),

                "next_protocol": (
                    features.next_protocol
                ),

                "ssl_history": (
                    features.ssl_history
                ),

                "ja4": features.ja4,
                "ja4s": features.ja4s,

                "ja4_present": (
                    features.has_ja4
                ),

                "ja4s_present": (
                    features.has_ja4s
                ),

                "unique_ja4_count": len(
                    unique_ja4
                ),

                "unique_ja4s_count": len(
                    unique_ja4s
                ),

                "periodicity_cv": (
                    round(
                        regularity_cv,
                        4,
                    )
                    if regularity_cv is not None
                    else None
                ),

                "periodicity_signal": round(
                    periodicity_signal,
                    4,
                ),

                "anomaly_signals": (
                    anomaly_signals
                ),

                "supporting_signal_count": (
                    supporting_signals
                ),

                "score_threshold": (
                    self.score_threshold
                ),

                "minimum_supporting_signals": (
                    self.minimum_supporting_signals
                ),

                "payload_decryption": False,
            },
        )
