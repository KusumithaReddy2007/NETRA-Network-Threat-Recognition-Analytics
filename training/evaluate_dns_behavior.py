from __future__ import annotations

import random
import time
from collections import defaultdict

import pandas as pd

from backend.app.services.dns.dns_detector import DNSBehaviorEngine
from backend.app.services.dns.dns_reader import ZeekDNSRecord


TEST_PATH = "datasets/raw/dns_threats/test_combined_multiclass.csv.gz"

# Keep the benchmark manageable while retaining all tunnel examples.
BENIGN_SAMPLE = 10000
DGA_SAMPLE = 10000
TUNNEL_SAMPLE = None

QUERIES_PER_SOURCE = 100
QUERY_INTERVAL = 1.0

RANDOM_SEED = 42


def make_record(
    timestamp: float,
    source_ip: str,
    domain: str,
) -> ZeekDNSRecord:
    return ZeekDNSRecord(
        fields={
            "ts": str(timestamp),
            "id.orig_h": source_ip,
            "query": domain,
            "qtype_name": "A",
        }
    )


def evaluate_class(
    domains: list[str],
    label_name: str,
    source_prefix: str,
) -> dict:

    results = []

    # Split domains into simulated independent sources.
    streams = [
        domains[i:i + QUERIES_PER_SOURCE]
        for i in range(
            0,
            len(domains),
            QUERIES_PER_SOURCE,
        )
    ]

    for stream_index, stream in enumerate(streams):
        if not stream:
            continue

        engine = DNSBehaviorEngine()

        source_ip = f"10.{stream_index // 254 + 1}.{stream_index % 254 + 1}.50"

        triggered = False
        first_trigger_query = None
        max_score = 0.0
        final_evidence = {}

        base_timestamp = 1_000_000.0 + (
            stream_index * 10_000.0
        )

        for query_index, domain in enumerate(stream):
            timestamp = (
                base_timestamp
                + query_index * QUERY_INTERVAL
            )

            record = make_record(
                timestamp,
                source_ip,
                domain,
            )

            detections = engine.analyze(record)

            tunnel = next(
                (
                    detection
                    for detection in detections
                    if detection.threat_class == "DNS_TUNNEL"
                ),
                None,
            )

            if tunnel is None:
                continue

            max_score = max(
                max_score,
                tunnel.score,
            )

            final_evidence = tunnel.evidence

            if tunnel.triggered and not triggered:
                triggered = True
                first_trigger_query = query_index + 1

        results.append(
            {
                "label": label_name,
                "source_ip": source_ip,
                "query_count": len(stream),
                "triggered": triggered,
                "first_trigger_query": first_trigger_query,
                "max_score": max_score,
                "supporting_signals": final_evidence.get(
                    "supporting_signal_count",
                    0,
                ),
            }
        )

    return results


def summarize(
    results: list[dict],
    label_name: str,
) -> None:

    total = len(results)
    alerts = sum(
        result["triggered"]
        for result in results
    )

    alert_rate = (
        alerts / total * 100.0
        if total
        else 0.0
    )

    detection_latencies = [
        result["first_trigger_query"]
        for result in results
        if result["first_trigger_query"] is not None
    ]

    average_latency = (
        sum(detection_latencies)
        / len(detection_latencies)
        if detection_latencies
        else None
    )

    maximum_score = max(
        (result["max_score"] for result in results),
        default=0.0,
    )

    print()
    print("=" * 72)
    print(label_name)
    print("=" * 72)
    print("Simulated sources:", total)
    print("Triggered sources:", alerts)
    print("Alert rate:       {:.2f}%".format(alert_rate))
    print("Maximum score:    {:.2f}".format(maximum_score))

    if average_latency is not None:
        print(
            "Average detection query:",
            round(average_latency, 2),
        )


def main() -> None:
    random.seed(RANDOM_SEED)

    print("=" * 72)
    print("NETRA DNS BEHAVIORAL BENCHMARK")
    print("=" * 72)

    print("\nLoading independent test set...")

    df = pd.read_csv(TEST_PATH)

    print("Total rows:", len(df))

    # Remove exact duplicate domain/class pairs.
    df = df.drop_duplicates(
        subset=["domain", "class"]
    ).reset_index(drop=True)

    print("After deduplication:", len(df))

    benign = (
        df[df["class"] == 0]["domain"]
        .astype(str)
        .tolist()
    )

    dga = (
        df[df["class"] == 1]["domain"]
        .astype(str)
        .tolist()
    )

    tunnel = (
        df[df["class"] == 2]["domain"]
        .astype(str)
        .tolist()
    )

    random.shuffle(benign)
    random.shuffle(dga)
    random.shuffle(tunnel)

    benign = benign[:BENIGN_SAMPLE]
    dga = dga[:DGA_SAMPLE]

    if TUNNEL_SAMPLE is not None:
        tunnel = tunnel[:TUNNEL_SAMPLE]

    print()
    print("Benchmark samples:")
    print("BENIGN:", len(benign))
    print("DGA:   ", len(dga))
    print("TUNNEL:", len(tunnel))

    start = time.perf_counter()

    benign_results = evaluate_class(
        benign,
        "BENIGN",
        "benign",
    )

    dga_results = evaluate_class(
        dga,
        "DGA",
        "dga",
    )

    tunnel_results = evaluate_class(
        tunnel,
        "DNS_TUNNEL",
        "tunnel",
    )

    elapsed = time.perf_counter() - start

    summarize(
        benign_results,
        "BENIGN — FALSE POSITIVE TEST",
    )

    summarize(
        dga_results,
        "DGA — FALSE POSITIVE TEST",
    )

    summarize(
        tunnel_results,
        "DNS TUNNEL — DETECTION TEST",
    )

    benign_alerts = sum(
        result["triggered"]
        for result in benign_results
    )

    dga_alerts = sum(
        result["triggered"]
        for result in dga_results
    )

    tunnel_alerts = sum(
        result["triggered"]
        for result in tunnel_results
    )

    tunnel_total = len(tunnel_results)

    tunnel_recall = (
        tunnel_alerts / tunnel_total * 100.0
        if tunnel_total
        else 0.0
    )

    false_alert_sources = (
        benign_alerts + dga_alerts
    )

    all_negative_sources = (
        len(benign_results)
        + len(dga_results)
    )

    false_positive_rate = (
        false_alert_sources
        / all_negative_sources
        * 100.0
        if all_negative_sources
        else 0.0
    )

    print()
    print("=" * 72)
    print("OVERALL BEHAVIORAL RESULTS")
    print("=" * 72)

    print(
        "DNS tunnel source recall: {:.2f}%".format(
            tunnel_recall
        )
    )

    print(
        "Negative-source false-positive rate: {:.2f}%".format(
            false_positive_rate
        )
    )

    print("Total benchmark time: {:.2f} sec".format(elapsed))

    print()
    print("Interpretation:")
    print(
        "This is a simulated stream benchmark because the source "
        "dataset contains domains/classes but no timestamps or source IPs."
    )


if __name__ == "__main__":
    main()
