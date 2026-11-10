from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from math import log2
from time import perf_counter
from typing import Any, Iterable

from .feature_extractor import safe_ratio
from .flow_normalizer import NetraFlow
from app.services.alert_service import create_behavioral_alert

# Known infrastructure services that commonly generate legitimate
# periodic traffic. Periodicity alone should not classify these
# connections as BOT_C2.
BENIGN_PERIODIC_SERVICES = {
    ("udp", 123): "NTP",
}

@dataclass
class DetectionResult:
    detector: str
    threat_class: str
    score: float
    triggered: bool
    evidence: dict[str, Any] = field(default_factory=dict)


class SlidingWindowState:
    """
    Incremental state maintained over a bounded time window.

    This is deliberately stateful so NETRA can detect behaviors that
    cannot be identified reliably from one isolated flow.
    """

    def __init__(self, window_seconds: float = 10.0) -> None:
        self.window_seconds = window_seconds

        self.flows: deque[NetraFlow] = deque()

        self.source_events: dict[str, deque[NetraFlow]] = defaultdict(deque)
        self.source_ports: dict[str, set[int]] = defaultdict(set)
        self.source_hosts: dict[str, set[str]] = defaultdict(set)

        self.destination_sources: dict[str, set[str]] = defaultdict(set)

        self.source_outbound_bytes: dict[str, int] = defaultdict(int)
        self.source_inbound_bytes: dict[str, int] = defaultdict(int)

    def add(self, flow: NetraFlow) -> None:
        self.flows.append(flow)

        self.source_events[flow.src_ip].append(flow)
        self.source_ports[flow.src_ip].add(flow.dst_port)
        self.source_hosts[flow.src_ip].add(flow.dst_ip)

        self.destination_sources[flow.dst_ip].add(flow.src_ip)

        self.source_outbound_bytes[flow.src_ip] += flow.orig_bytes
        self.source_inbound_bytes[flow.src_ip] += flow.resp_bytes

        self.expire(flow.timestamp)

    def expire(self, current_timestamp: float) -> None:
        cutoff = current_timestamp - self.window_seconds

        while self.flows and self.flows[0].timestamp < cutoff:
            old = self.flows.popleft()

            source_queue = self.source_events.get(old.src_ip)
            if source_queue:
                while source_queue and source_queue[0].timestamp < cutoff:
                    source_queue.popleft()

        # Rebuild bounded aggregates from active flows.
        self.source_ports.clear()
        self.source_hosts.clear()
        self.destination_sources.clear()
        self.source_outbound_bytes.clear()
        self.source_inbound_bytes.clear()

        for flow in self.flows:
            self.source_ports[flow.src_ip].add(flow.dst_port)
            self.source_hosts[flow.src_ip].add(flow.dst_ip)

            self.destination_sources[flow.dst_ip].add(flow.src_ip)

            self.source_outbound_bytes[flow.src_ip] += flow.orig_bytes
            self.source_inbound_bytes[flow.src_ip] += flow.resp_bytes


def shannon_entropy(values: Iterable[str]) -> float:
    values = list(values)

    if not values:
        return 0.0

    counts: dict[str, int] = defaultdict(int)

    for value in values:
        counts[value] += 1

    total = len(values)
    entropy = 0.0

    for count in counts.values():
        probability = count / total

        if probability > 0:
            entropy -= probability * log2(probability)

    return entropy


class BehavioralDetector:
    """
    Rule/statistical detectors corresponding directly to SIH26145.
    """

    def __init__(
        self,
        window_seconds: float = 10.0,
        ddos_rate_threshold: float = 100.0,
        scan_port_threshold: int = 20,
        scan_host_threshold: int = 20,
        exfil_ratio_threshold: float = 10.0,
        beacon_min_events: int = 4,
    ) -> None:
        self.window_seconds = window_seconds

        self.ddos_rate_threshold = ddos_rate_threshold
        self.scan_port_threshold = scan_port_threshold
        self.scan_host_threshold = scan_host_threshold
        self.exfil_ratio_threshold = exfil_ratio_threshold
        self.beacon_min_events = beacon_min_events

    def detect_ddos(
        self,
        flow: NetraFlow,
        state: SlidingWindowState,
    ) -> DetectionResult:
        source_flows = state.source_events.get(flow.src_ip, ())

        flow_count = len(source_flows)

        observed_rate = safe_ratio(
            flow_count,
            self.window_seconds,
        )

        source_entropy = shannon_entropy(
            item.src_ip
            for item in state.flows
            if item.dst_ip == flow.dst_ip
        )

        syn_like = (
            flow.protocol == "tcp"
            and flow.orig_pkts <= 3
            and flow.resp_pkts <= 1
        )

        rate_score = min(
            observed_rate / max(self.ddos_rate_threshold, 1.0),
            1.0,
        )

        entropy_score = 1.0 if source_entropy >= 2.5 else source_entropy / 2.5

        protocol_score = 1.0 if syn_like or flow.protocol == "udp" else 0.0

        score = (
            0.50 * rate_score
            + 0.25 * entropy_score
            + 0.25 * protocol_score
        )

        triggered = (
            observed_rate >= self.ddos_rate_threshold
            or (
                observed_rate >= self.ddos_rate_threshold * 0.5
                and (syn_like or flow.protocol == "udp")
                and source_entropy >= 1.5
            )
        )

        return DetectionResult(
            detector="ddos_behavior",
            threat_class="DDOS",
            score=round(score * 100, 2),
            triggered=triggered,
            evidence={
                "window_seconds": self.window_seconds,
                "source_flow_count": flow_count,
                "source_flow_rate": round(observed_rate, 3),
                "destination_source_entropy": round(source_entropy, 3),
                "protocol": flow.protocol,
                "syn_like_pattern": syn_like,
            },
        )

    def detect_port_scan(
        self,
        flow: NetraFlow,
        state: SlidingWindowState,
    ) -> DetectionResult:
        ports = len(state.source_ports.get(flow.src_ip, set()))
        hosts = len(state.source_hosts.get(flow.src_ip, set()))

        port_score = min(ports / max(self.scan_port_threshold, 1), 1.0)
        host_score = min(hosts / max(self.scan_host_threshold, 1), 1.0)

        score = max(port_score, host_score)

        triggered = (
            ports >= self.scan_port_threshold
            or hosts >= self.scan_host_threshold
        )

        return DetectionResult(
            detector="port_scan_fanout",
            threat_class="PORTSCAN",
            score=round(score * 100, 2),
            triggered=triggered,
            evidence={
                "window_seconds": self.window_seconds,
                "unique_destination_ports": ports,
                "unique_destination_hosts": hosts,
                "source_ip": flow.src_ip,
            },
        )

    def detect_exfiltration(
        self,
        flow: NetraFlow,
        state: SlidingWindowState,
    ) -> DetectionResult:
        outbound = state.source_outbound_bytes.get(flow.src_ip, 0)
        inbound = state.source_inbound_bytes.get(flow.src_ip, 0)

        ratio = safe_ratio(outbound, inbound)

        ratio_score = min(
            ratio / max(self.exfil_ratio_threshold, 1.0),
            1.0,
        )

        # Stronger evidence when significant outbound volume is observed.
        volume_score = min(outbound / (10 * 1024 * 1024), 1.0)

        score = 0.70 * ratio_score + 0.30 * volume_score

        triggered = (
            ratio >= self.exfil_ratio_threshold
            and outbound >= 1 * 1024 * 1024
        )

        return DetectionResult(
            detector="exfiltration_asymmetry",
            threat_class="EXFILTRATION",
            score=round(score * 100, 2),
            triggered=triggered,
            evidence={
                "window_seconds": self.window_seconds,
                "outbound_bytes": outbound,
                "inbound_bytes": inbound,
                "outbound_inbound_ratio": round(ratio, 3),
            },
        )

    def detect_c2_beacon(
        self,
        flow: NetraFlow,
        state: SlidingWindowState,
    ) -> DetectionResult:
        protocol = str(flow.protocol or "").lower()

        service_key = (
            protocol,
            int(flow.dst_port),
        )

        benign_service = BENIGN_PERIODIC_SERVICES.get(
            service_key
        )

        # Compare flows using destination IP + destination port +
        # protocol. This prevents unrelated services on the same host
        # from being combined into one beaconing pattern.
        events = list(
            state.source_events.get(
                flow.src_ip,
                (),
            )
        )

        same_destination = [
            item
            for item in events
            if (
                item.dst_ip == flow.dst_ip
                and int(item.dst_port) == int(flow.dst_port)
                and str(item.protocol or "").lower() == protocol
            )
        ]

        # Known legitimate periodic infrastructure traffic should not
        # trigger BOT_C2 based on periodicity alone.
        if benign_service:
            return DetectionResult(
                detector="c2_beacon_periodicity",
                threat_class="BOT_C2",
                score=0.0,
                triggered=False,
                evidence={
                    "event_count": len(same_destination),
                    "destination": flow.dst_ip,
                    "destination_port": flow.dst_port,
                    "protocol": protocol,
                    "benign_service": benign_service,
                    "suppressed_reason": (
                        "known_legitimate_periodic_service"
                    ),
                    "periodicity_cv": None,
                },
            )

        if len(same_destination) < self.beacon_min_events:
            return DetectionResult(
                detector="c2_beacon_periodicity",
                threat_class="BOT_C2",
                score=0.0,
                triggered=False,
                evidence={
                    "event_count": len(same_destination),
                    "periodicity_cv": None,
                    "destination": flow.dst_ip,
                    "destination_port": flow.dst_port,
                    "protocol": protocol,
                },
            )

        timestamps = [
            item.timestamp
            for item in same_destination
        ]

        intervals = [
            b - a
            for a, b in zip(
                timestamps,
                timestamps[1:],
            )
            if b > a
        ]

        if len(intervals) < 3:
            return DetectionResult(
                detector="c2_beacon_periodicity",
                threat_class="BOT_C2",
                score=0.0,
                triggered=False,
                evidence={
                    "event_count": len(same_destination),
                    "periodicity_cv": None,
                    "destination": flow.dst_ip,
                    "destination_port": flow.dst_port,
                    "protocol": protocol,
                },
            )

        mean_interval = (
            sum(intervals)
            / len(intervals)
        )

        variance = (
            sum(
                (interval - mean_interval) ** 2
                for interval in intervals
            )
            / len(intervals)
        )

        stddev = variance ** 0.5

        coefficient_of_variation = safe_ratio(
            stddev,
            mean_interval,
        )

        periodicity_score = max(
            0.0,
            1.0 - coefficient_of_variation,
        )

        triggered = (
            len(same_destination)
            >= self.beacon_min_events
            and coefficient_of_variation <= 0.20
        )

        return DetectionResult(
            detector="c2_beacon_periodicity",
            threat_class="BOT_C2",
            score=round(
                periodicity_score * 100,
                2,
            ),
            triggered=triggered,
            evidence={
                "event_count": len(same_destination),
                "destination": flow.dst_ip,
                "destination_port": flow.dst_port,
                "protocol": protocol,
                "mean_interarrival_seconds": round(
                    mean_interval,
                    4,
                ),
                "interarrival_stddev": round(
                    stddev,
                    4,
                ),
                "periodicity_cv": round(
                    coefficient_of_variation,
                    4,
                ),
                "window_seconds": self.window_seconds,
            },
        )


class StreamingDetectionEngine:
    """
    Processes flows incrementally.

    No complete end-of-run batch is required.
    """

    def __init__(
        self,
        window_seconds: float = 10.0,
    ) -> None:
        self.state = SlidingWindowState(window_seconds)
        self.detector = BehavioralDetector(window_seconds)

    def process_flow(self, flow: NetraFlow) -> dict[str, Any]:
        start = perf_counter()

        self.state.add(flow)

        detections = [
            self.detector.detect_ddos(flow, self.state),
            self.detector.detect_port_scan(flow, self.state),
            self.detector.detect_c2_beacon(flow, self.state),
            self.detector.detect_exfiltration(flow, self.state),
        ]

        triggered_results = [
            result
            for result in detections
            if result.triggered
        ]

        triggered = [
            {
                "detector": result.detector,
                "threat_class": result.threat_class,
                "score": result.score,
                "evidence": result.evidence,
            }
            for result in triggered_results
        ]

        alerts = []

        for result in triggered_results:
            alerts.append(
                create_behavioral_alert(
                    flow_id=flow.flow_id,
                    timestamp=str(flow.timestamp),
                    threat_class=result.threat_class,
                    confidence=float(result.score),
                    supporting_evidence=result.evidence,
                )
            )

        elapsed_ms = (perf_counter() - start) * 1000

        return {
            "flow_id": flow.flow_id,
            "timestamp": flow.timestamp,
            "behavioral_detections": triggered,
            "alerts": alerts,
            "processing_latency_ms": round(elapsed_ms, 3),
        }
