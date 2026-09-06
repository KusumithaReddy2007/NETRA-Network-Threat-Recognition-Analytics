from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import Any


@dataclass
class TLSC2BeaconDetection:
    detector: str
    threat_class: str
    score: float
    triggered: bool
    evidence: dict[str, Any]


class TLSC2BeaconEngine:
    """
    Metadata-only encrypted C2 beacon detector.

    Detects repeated TLS communications that:
      - originate from the same source
      - target the same destination
      - reuse the same JA4/JA4S
      - occur repeatedly within a bounded window
      - have regular inter-arrival timing

    JA4/JA4S are grouping/context features only.
    They are not treated as standalone malicious fingerprints.
    """

    def __init__(
        self,
        window_seconds: float = 180.0,
        minimum_events: int = 4,
        max_cv: float = 0.20,
        min_interval: float = 5.0,
        max_interval: float = 60.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.minimum_events = minimum_events
        self.max_cv = max_cv
        self.min_interval = min_interval
        self.max_interval = max_interval

        self.events: dict[
            tuple[str, str, str, str],
            deque[float],
        ] = defaultdict(deque)

    @staticmethod
    def _cv(timestamps: list[float]) -> float:
        if len(timestamps) < 4:
            return 1.0

        intervals = [
            b - a
            for a, b in zip(
                timestamps,
                timestamps[1:],
            )
            if b > a
        ]

        if len(intervals) < 3:
            return 1.0

        avg = mean(intervals)

        if avg <= 0:
            return 1.0

        return pstdev(intervals) / avg

    def analyze(
        self,
        fields: dict[str, str],
    ) -> TLSC2BeaconDetection:

        try:
            timestamp = float(
                fields.get("ts", 0.0) or 0.0
            )
        except (TypeError, ValueError):
            timestamp = 0.0

        source = str(
            fields.get("id.orig_h", "")
            or "unknown"
        )

        destination = str(
            fields.get("id.resp_h", "")
            or ""
        )

        ja4 = str(
            fields.get("ja4", "")
            or ""
        )

        ja4s = str(
            fields.get("ja4s", "")
            or ""
        )

        # Cannot establish encrypted-C2 beaconing without
        # a stable TLS fingerprint pair.
        if not ja4 or not ja4s or not destination:
            return TLSC2BeaconDetection(
                detector="tls_c2_beacon",
                threat_class="BOT_C2",
                score=0.0,
                triggered=False,
                evidence={
                    "reason": "insufficient_tls_metadata",
                    "source_ip": source,
                    "destination_ip": destination,
                },
            )

        key = (
            source,
            destination,
            ja4,
            ja4s,
        )

        queue = self.events[key]
        queue.append(timestamp)

        cutoff = timestamp - self.window_seconds

        while queue and queue[0] < cutoff:
            queue.popleft()

        timestamps = list(queue)

        cv = self._cv(timestamps)

        intervals = [
            b - a
            for a, b in zip(
                timestamps,
                timestamps[1:],
            )
            if b > a
        ]

        average_interval = (
            mean(intervals)
            if intervals
            else 0.0
        )

        triggered = (
            len(timestamps) >= self.minimum_events
            and self.min_interval
            <= average_interval
            <= self.max_interval
            and cv <= self.max_cv
        )

        # Score is continuous and reflects timing regularity
        # plus repeated-event evidence.
        if len(timestamps) < self.minimum_events:
            score = min(
                40.0,
                10.0 * len(timestamps),
            )
        else:
            regularity_score = max(
                0.0,
                min(
                    1.0,
                    (
                        self.max_cv - cv
                    ) / self.max_cv,
                ),
            )

            count_score = min(
                1.0,
                len(timestamps) / 6.0,
            )

            interval_score = (
                1.0
                if (
                    self.min_interval
                    <= average_interval
                    <= self.max_interval
                )
                else 0.0
            )

            score = 100.0 * (
                0.55 * regularity_score
                + 0.30 * count_score
                + 0.15 * interval_score
            )

        return TLSC2BeaconDetection(
            detector="tls_c2_beacon",
            threat_class="BOT_C2",
            score=round(score, 2),
            triggered=triggered,
            evidence={
                "source_ip": source,
                "destination_ip": destination,
                "ja4": ja4,
                "ja4s": ja4s,
                "window_seconds": self.window_seconds,
                "event_count": len(timestamps),
                "average_interval_seconds": round(
                    average_interval,
                    4,
                ),
                "coefficient_of_variation": round(
                    cv,
                    4,
                ),
                "min_interval_seconds": self.min_interval,
                "max_interval_seconds": self.max_interval,
                "payload_decryption": False,
            },
        )
