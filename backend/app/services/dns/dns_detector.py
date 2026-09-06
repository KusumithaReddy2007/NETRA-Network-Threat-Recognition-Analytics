from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any

from .dns_features import DNSFeatures, extract_dns_features
from .dns_reader import ZeekDNSRecord


@dataclass
class DNSDetection:
    detector: str
    threat_class: str
    score: float
    triggered: bool
    evidence: dict[str, Any]


class DNSBehaviorEngine:
    """
    Streaming DNS behavioral detector.

    The detector evaluates DNS activity from a source over a sliding window
    rather than deciding from a single unusual domain.

    High entropy, long labels, or digits alone are NOT considered proof of
    DNS tunnelling. A detection requires multiple corroborating signals.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        minimum_queries: int = 8,
        long_query_length: int = 45,
        very_long_query_length: int = 60,
        high_entropy_threshold: float = 3.6,
        tunnel_entropy_threshold: float = 3.2,
        tunnel_long_query_ratio: float = 0.40,
        tunnel_average_length: float = 42.0,
        burst_rate_threshold: float = 0.50,
        uniqueness_threshold: float = 0.70,
        tunnel_score_threshold: float = 68.0,
        record_type_window_seconds: float = 60.0,
        record_type_minimum_queries: int = 8,
        record_type_dominance_threshold: float = 0.60,
        suspicious_record_types: set[str] | None = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.minimum_queries = minimum_queries
        self.long_query_length = long_query_length
        self.very_long_query_length = very_long_query_length
        self.high_entropy_threshold = high_entropy_threshold
        self.tunnel_entropy_threshold = tunnel_entropy_threshold
        self.tunnel_long_query_ratio = tunnel_long_query_ratio
        self.tunnel_average_length = tunnel_average_length
        self.burst_rate_threshold = burst_rate_threshold
        self.uniqueness_threshold = uniqueness_threshold
        self.tunnel_score_threshold = tunnel_score_threshold

        # source IP -> [(timestamp, DNSFeatures)]
        self.events: dict[str, deque[tuple[float, DNSFeatures]]] = defaultdict(
            deque
        )

        # source IP -> [(timestamp, qtype_name)]
        self.record_type_events: dict[
            str, deque[tuple[float, str]]
        ] = defaultdict(deque)

        self.record_type_window_seconds = record_type_window_seconds
        self.record_type_minimum_queries = record_type_minimum_queries
        self.record_type_dominance_threshold = (
            record_type_dominance_threshold
        )

        # These types are not inherently malicious. They are treated only
        # as higher-interest metadata when they dominate recent activity.
        self.suspicious_record_types = (
            suspicious_record_types
            or {
                "TXT",
                "NULL",
                "ANY",
                "SRV",
                "MX",
            }
        )

    # ------------------------------------------------------------------
    # Window management
    # ------------------------------------------------------------------

    def _expire(self, source: str, timestamp: float) -> None:
        cutoff = timestamp - self.window_seconds
        queue = self.events[source]

        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _add_event(
        self,
        source: str,
        timestamp: float,
        features: DNSFeatures,
    ) -> None:
        queue = self.events[source]
        queue.append((timestamp, features))
        self._expire(source, timestamp)

    def _expire_record_types(
        self,
        source: str,
        timestamp: float,
    ) -> None:
        cutoff = timestamp - self.record_type_window_seconds
        queue = self.record_type_events[source]

        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def _add_record_type_event(
        self,
        source: str,
        timestamp: float,
        qtype_name: str,
    ) -> None:
        queue = self.record_type_events[source]
        queue.append((timestamp, qtype_name))
        self._expire_record_types(source, timestamp)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @staticmethod
    def _safe_ratio(numerator: float, denominator: float) -> float:
        return numerator / denominator if denominator else 0.0

    @staticmethod
    def _coefficient_of_variation(timestamps: list[float]) -> float:
        if len(timestamps) < 3:
            return 1.0

        timestamps = sorted(timestamps)

        intervals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
            if timestamps[i] > timestamps[i - 1]
        ]

        if len(intervals) < 2:
            return 1.0

        avg = mean(intervals)

        if avg <= 0:
            return 1.0

        return pstdev(intervals) / avg

    # ------------------------------------------------------------------
    # DGA anomaly detector
    # ------------------------------------------------------------------

    def _dga_detection(
        self,
        source: str,
        features: DNSFeatures,
    ) -> DNSDetection:

        length_signal = self._clamp(
            features.longest_label_length / 45.0
        )

        entropy_signal = self._clamp(
            features.max_label_entropy / max(
                self.high_entropy_threshold,
                0.1,
            )
        )

        digit_signal = self._clamp(
            features.digit_ratio / 0.30
        )

        low_vowel_signal = (
            1.0
            if (
                features.vowel_ratio < 0.20
                and features.query_length >= 20
            )
            else 0.0
        )

        suspicious_tld_signal = (
            1.0
            if features.suspicious_tld
            else 0.0
        )

        score = (
            0.25 * length_signal
            + 0.25 * entropy_signal
            + 0.15 * digit_signal
            + 0.20 * low_vowel_signal
            + 0.15 * suspicious_tld_signal
        )

        triggered = (
            score >= 0.70
            and (
                length_signal >= 0.75
                or entropy_signal >= 0.90
            )
            and (
                digit_signal >= 0.35
                or low_vowel_signal >= 1.0
                or suspicious_tld_signal >= 1.0
            )
        )

        return DNSDetection(
            detector="dns_dga_anomaly",
            threat_class="DGA",
            score=round(score * 100.0, 2),
            triggered=triggered,
            evidence={
                "source_ip": source,
                "query": features.query,
                "query_length": features.query_length,
                "longest_label_length": features.longest_label_length,
                "entropy": round(features.entropy, 4),
                "max_label_entropy": round(
                    features.max_label_entropy,
                    4,
                ),
                "digit_ratio": round(features.digit_ratio, 4),
                "vowel_ratio": round(features.vowel_ratio, 4),
                "unique_char_ratio": round(
                    features.unique_char_ratio,
                    4,
                ),
                "suspicious_tld": bool(
                    features.suspicious_tld
                ),
            },
        )

    # ------------------------------------------------------------------
    # DNS tunnelling behavioral detector
    # ------------------------------------------------------------------

    def _tunnel_detection(
        self,
        source: str,
        queue: deque[tuple[float, DNSFeatures]],
    ) -> DNSDetection:

        count = len(queue)

        if count == 0:
            return DNSDetection(
                detector="dns_tunnelling_behavior",
                threat_class="DNS_TUNNEL",
                score=0.0,
                triggered=False,
                evidence={
                    "source_ip": source,
                    "window_seconds": self.window_seconds,
                    "query_count": 0,
                },
            )

        timestamps = [timestamp for timestamp, _ in queue]
        features_list = [features for _, features in queue]

        query_lengths = [
            feature.query_length
            for feature in features_list
        ]

        entropies = [
            feature.max_label_entropy
            for feature in features_list
        ]

        digit_ratios = [
            feature.digit_ratio
            for feature in features_list
        ]

        unique_queries = {
            feature.query
            for feature in features_list
            if feature.query
        }

        long_queries = [
            feature
            for feature in features_list
            if feature.query_length >= self.long_query_length
        ]

        very_long_queries = [
            feature
            for feature in features_list
            if feature.query_length >= self.very_long_query_length
        ]

        long_query_ratio = self._safe_ratio(
            len(long_queries),
            count,
        )

        very_long_query_ratio = self._safe_ratio(
            len(very_long_queries),
            count,
        )

        average_length = mean(query_lengths)

        max_length = max(query_lengths)

        average_entropy = mean(entropies)

        max_entropy = max(entropies)

        average_digit_ratio = mean(digit_ratios)

        unique_query_ratio = self._safe_ratio(
            len(unique_queries),
            count,
        )

        query_rate = count / max(self.window_seconds, 1.0)

        temporal_cv = self._coefficient_of_variation(
            timestamps
        )

        # High query volume alone is not sufficient. We use it only as
        # supporting evidence when the other characteristics also agree.
        burst_signal = self._clamp(
            query_rate / max(self.burst_rate_threshold, 0.01)
        )

        long_signal = self._clamp(
            long_query_ratio / max(
                self.tunnel_long_query_ratio,
                0.01,
            )
        )

        very_long_signal = self._clamp(
            very_long_query_ratio / 0.25
        )

        length_signal = self._clamp(
            average_length / max(
                self.tunnel_average_length,
                1.0,
            )
        )

        entropy_signal = self._clamp(
            average_entropy / max(
                self.tunnel_entropy_threshold,
                0.1,
            )
        )

        uniqueness_signal = self._clamp(
            unique_query_ratio / max(
                self.uniqueness_threshold,
                0.01,
            )
        )

        digit_signal = self._clamp(
            average_digit_ratio / 0.20
        )

        # Repeated, highly regular DNS queries are more consistent with
        # beaconing than with tunnelling, so regularity only contributes
        # weakly to the tunnel score.
        regularity_signal = (
            self._clamp(
                (0.50 - temporal_cv) / 0.50
            )
            if len(timestamps) >= 4
            else 0.0
        )

        score = 100.0 * (
            0.24 * long_signal
            + 0.12 * very_long_signal
            + 0.20 * length_signal
            + 0.20 * entropy_signal
            + 0.10 * uniqueness_signal
            + 0.08 * digit_signal
            + 0.06 * burst_signal
        )

        # Require multiple independent signals.
        supporting_signals = sum(
            [
                long_query_ratio >= self.tunnel_long_query_ratio,
                average_length >= self.tunnel_average_length,
                average_entropy >= self.tunnel_entropy_threshold,
                unique_query_ratio >= self.uniqueness_threshold,
                average_digit_ratio >= 0.20,
                len(very_long_queries) >= 3,
            ]
        )

        triggered = (
            count >= self.minimum_queries
            and score >= self.tunnel_score_threshold
            and supporting_signals >= 3
            and (
                long_query_ratio >= self.tunnel_long_query_ratio
                or average_entropy >= self.tunnel_entropy_threshold
            )
        )

        return DNSDetection(
            detector="dns_tunnelling_behavior",
            threat_class="DNS_TUNNEL",
            score=round(score, 2),
            triggered=triggered,
            evidence={
                "source_ip": source,
                "window_seconds": self.window_seconds,
                "query_count": count,
                "query_rate_per_second": round(
                    query_rate,
                    4,
                ),
                "unique_query_count": len(unique_queries),
                "unique_query_ratio": round(
                    unique_query_ratio,
                    4,
                ),
                "long_query_count": len(long_queries),
                "long_query_ratio": round(
                    long_query_ratio,
                    4,
                ),
                "very_long_query_count": len(
                    very_long_queries
                ),
                "very_long_query_ratio": round(
                    very_long_query_ratio,
                    4,
                ),
                "average_query_length": round(
                    average_length,
                    3,
                ),
                "max_query_length": max_length,
                "average_entropy": round(
                    average_entropy,
                    4,
                ),
                "max_entropy": round(
                    max_entropy,
                    4,
                ),
                "average_digit_ratio": round(
                    average_digit_ratio,
                    4,
                ),
                "temporal_coefficient_variation": round(
                    temporal_cv,
                    4,
                ),
                "regularity_support_signal": round(
                    regularity_signal,
                    4,
                ),
                "supporting_signal_count": supporting_signals,
            },
        )

    # ------------------------------------------------------------------
    # DNS record-type anomaly detector
    # ------------------------------------------------------------------

    def _record_type_detection(
        self,
        source: str,
        qtype_name: str,
    ) -> DNSDetection:
        queue = self.record_type_events[source]

        if not queue:
            return DNSDetection(
                detector="dns_record_type_anomaly",
                threat_class="DNS_RECORD_ANOMALY",
                score=0.0,
                triggered=False,
                evidence={
                    "source_ip": source,
                    "window_seconds": self.record_type_window_seconds,
                    "query_count": 0,
                    "record_type": qtype_name,
                },
            )

        counts: dict[str, int] = {}

        for _, value in queue:
            counts[value] = counts.get(value, 0) + 1

        total = len(queue)

        dominant_type, dominant_count = max(
            counts.items(),
            key=lambda item: item[1],
        )

        dominance = dominant_count / total if total else 0.0

        unusual_current_type = (
            qtype_name in self.suspicious_record_types
        )

        dominant_unusual_type = (
            dominant_type in self.suspicious_record_types
        )

        type_diversity = len(counts)

        anomaly_strength = 0.0

        if dominant_unusual_type:
            anomaly_strength += 0.60 * self._clamp(
                dominance / max(
                    self.record_type_dominance_threshold,
                    0.01,
                )
            )

        if unusual_current_type:
            anomaly_strength += 0.20

        # A sudden move from a narrow normal profile toward multiple
        # higher-interest record types is additional supporting evidence.
        if (
            type_diversity >= 3
            and dominant_unusual_type
        ):
            anomaly_strength += 0.20

        score = round(
            self._clamp(anomaly_strength) * 100.0,
            2,
        )

        triggered = (
            total >= self.record_type_minimum_queries
            and dominant_unusual_type
            and dominance >= self.record_type_dominance_threshold
            and score >= 60.0
        )

        return DNSDetection(
            detector="dns_record_type_anomaly",
            threat_class="DNS_RECORD_ANOMALY",
            score=score,
            triggered=triggered,
            evidence={
                "source_ip": source,
                "window_seconds": self.record_type_window_seconds,
                "query_count": total,
                "current_record_type": qtype_name,
                "dominant_record_type": dominant_type,
                "dominant_record_type_count": dominant_count,
                "dominant_record_type_ratio": round(
                    dominance,
                    4,
                ),
                "record_type_distribution": dict(
                    sorted(
                        counts.items(),
                        key=lambda item: (
                            -item[1],
                            item[0],
                        ),
                    )
                ),
                "record_type_diversity": type_diversity,
                "suspicious_record_types": sorted(
                    self.suspicious_record_types
                ),
            },
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        record: ZeekDNSRecord,
        reference_ngrams: dict[str, float] | None = None,
    ) -> list[DNSDetection]:

        fields = record.fields

        try:
            timestamp = float(
                fields.get("ts", 0.0) or 0.0
            )
        except (TypeError, ValueError):
            timestamp = 0.0

        query = str(
            fields.get("query", "") or ""
        ).strip()

        if not query:
            return []

        source = str(
            fields.get("id.orig_h", "")
            or "unknown"
        )

        qtype_name = str(
            fields.get("qtype_name", "")
            or ""
        ).strip().upper()

        if not qtype_name:
            qtype_name = "UNKNOWN"

        features = extract_dns_features(query)

        self._add_event(
            source,
            timestamp,
            features,
        )

        self._add_record_type_event(
            source,
            timestamp,
            qtype_name,
        )

        queue = self.events[source]

        dga_detection = self._dga_detection(
            source,
            features,
        )

        tunnel_detection = self._tunnel_detection(
            source,
            queue,
        )

        record_type_detection = self._record_type_detection(
            source,
            qtype_name,
        )

        return [
            dga_detection,
            tunnel_detection,
            record_type_detection,
        ]


def analyze_zeek_dns_log(
    path: str,
    reference_ngrams: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """
    Offline replay helper for a Zeek dns.log file.
    """

    from .dns_reader import ZeekDNSTSVReader

    engine = DNSBehaviorEngine()
    reader = ZeekDNSTSVReader(path)

    results: list[dict[str, Any]] = []

    for record in reader:
        detections = engine.analyze(
            record,
            reference_ngrams=reference_ngrams,
        )

        for detection in detections:
            results.append(
                {
                    "detector": detection.detector,
                    "threat_class": detection.threat_class,
                    "score": detection.score,
                    "triggered": detection.triggered,
                    "evidence": detection.evidence,
                }
            )

    return results
