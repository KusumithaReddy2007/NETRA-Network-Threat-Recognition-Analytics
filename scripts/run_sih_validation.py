from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = BASE_DIR / "docs"
OUTPUT_FILE = OUTPUT_DIR / "SIH26145_FINAL_VALIDATION.json"

# Make the backend importable for this script.
sys.path.insert(0, str(BASE_DIR / "backend"))

from app.services.alert_service import create_behavioral_alert
from app.services.ingestion.flow_normalizer import NetraFlow
from app.services.ingestion.stream_processor import StreamingDetectionEngine


def run_command(name: str, command: list[str]) -> dict[str, Any]:
    print()
    print("=" * 78)
    print(name)
    print("=" * 78)
    print("$", " ".join(command))

    env = dict(os.environ)
    env["PYTHONPATH"] = f"{BASE_DIR / 'backend'}:{BASE_DIR}"

    started = datetime.now(timezone.utc)

    completed = subprocess.run(
        command,
        cwd=BASE_DIR,
        env=env,
        text=True,
        capture_output=True,
    )

    finished = datetime.now(timezone.utc)

    if completed.stdout:
        print(completed.stdout)

    if completed.stderr:
        print(completed.stderr, file=sys.stderr)

    return {
        "name": name,
        "command": command,
        "return_code": completed.returncode,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def make_flow(
    *,
    timestamp: float,
    flow_id: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str = "tcp",
    service: str = "http",
    duration: float = 0.01,
    orig_bytes: int = 60,
    resp_bytes: int = 0,
    orig_pkts: int = 1,
    resp_pkts: int = 0,
    conn_state: str = "S0",
    history: str = "S",
) -> NetraFlow:
    return NetraFlow(
        timestamp=timestamp,
        flow_id=flow_id,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        service=service,
        duration=duration,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_pkts=orig_pkts,
        resp_pkts=resp_pkts,
        conn_state=conn_state,
        history=history,
    )


def run_behavioral_test(
    name: str,
    expected_threat: str,
    flows: list[NetraFlow],
) -> dict[str, Any]:
    engine = StreamingDetectionEngine(window_seconds=10.0)

    triggered = []

    latencies = []

    for flow in flows:
        result = engine.process_flow(flow)

        latencies.append(
            float(result["processing_latency_ms"])
        )

        for detection in result["behavioral_detections"]:
            triggered.append(
                {
                    "flow_id": result["flow_id"],
                    "timestamp": result["timestamp"],
                    **detection,
                }
            )

    matching = [
        item
        for item in triggered
        if item["threat_class"] == expected_threat
    ]

    passed = bool(matching)

    standardized_alert = None

    if matching:
        detection = matching[-1]

        standardized_alert = create_behavioral_alert(
            flow_id=str(detection["flow_id"]),
            timestamp=str(detection["timestamp"]),
            threat_class=detection["threat_class"],
            confidence=float(detection["score"]),
            supporting_evidence=detection["evidence"],
        )

    required_alert_fields = {
        "alert_id",
        "timestamp",
        "flow_id",
        "threat_class",
        "confidence",
        "severity",
        "supporting_evidence",
    }

    alert_schema_valid = (
        standardized_alert is not None
        and required_alert_fields.issubset(
            standardized_alert.keys()
        )
    )

    print()
    print(f"[{name}]")
    print(f"Expected threat:     {expected_threat}")
    print(f"Triggered detections:{len(triggered)}")
    print(f"Matching detections: {len(matching)}")
    print(f"Detection result:    {'PASS' if passed else 'FAIL'}")
    print(
        "Alert schema:        "
        f"{'PASS' if alert_schema_valid else 'N/A'}"
    )

    if matching:
        print(
            f"Score:               "
            f"{matching[-1]['score']}"
        )

    return {
        "name": name,
        "expected_threat": expected_threat,
        "passed": passed,
        "matching_detections": matching,
        "all_triggered_detections": triggered,
        "average_latency_ms": (
            statistics.mean(latencies)
            if latencies
            else None
        ),
        "standardized_alert": standardized_alert,
        "alert_schema_valid": alert_schema_valid,
    }


def run_behavioral_validation() -> list[dict[str, Any]]:
    base = time.time()

    results = []

    # ------------------------------------------------------------
    # DDoS: irregular high-rate SYN-like flow
    # ------------------------------------------------------------
    ddos_gaps = [0.0007, 0.0013, 0.0009, 0.0017, 0.0008]

    ddos_flows = []
    ts = base

    for i in range(1200):
        ts += ddos_gaps[i % len(ddos_gaps)]

        ddos_flows.append(
            make_flow(
                timestamp=ts,
                flow_id=f"DDOS-{i}",
                src_ip="10.10.10.10",
                src_port=40000 + (i % 500),
                dst_ip="10.20.20.20",
                dst_port=80,
            )
        )

    results.append(
        run_behavioral_test(
            "DDoS behavioral test",
            "DDOS",
            ddos_flows,
        )
    )

    # ------------------------------------------------------------
    # Port scan: irregular destination-port fan-out
    # ------------------------------------------------------------
    portscan_flows = []

    for i in range(30):
        portscan_flows.append(
            make_flow(
                timestamp=base + i * 0.0137,
                flow_id=f"SCAN-{i}",
                src_ip="10.30.30.30",
                src_port=41000 + i,
                dst_ip="10.40.40.40",
                dst_port=1000 + i,
                duration=0.001,
                orig_bytes=60,
                resp_bytes=0,
                orig_pkts=1,
                resp_pkts=0,
                conn_state="S0",
                history="S",
            )
        )

    results.append(
        run_behavioral_test(
            "Port scan behavioral test",
            "PORTSCAN",
            portscan_flows,
        )
    )

    # ------------------------------------------------------------
    # C2 beacon: regular 2-second periodic connections
    # ------------------------------------------------------------
    c2_flows = []

    for i in range(12):
        c2_flows.append(
            make_flow(
                timestamp=base + i * 2.0,
                flow_id=f"C2-{i}",
                src_ip="10.50.50.50",
                src_port=42000 + i,
                dst_ip="10.60.60.60",
                dst_port=443,
                service="ssl",
                orig_bytes=120,
                resp_bytes=240,
                orig_pkts=2,
                resp_pkts=2,
                conn_state="SF",
                history="ShAd",
            )
        )

    results.append(
        run_behavioral_test(
            "C2 beacon behavioral test",
            "BOT_C2",
            c2_flows,
        )
    )

    # ------------------------------------------------------------
    # Exfiltration: large asymmetric outbound volume
    # ------------------------------------------------------------
    exfil_flow = make_flow(
        timestamp=base,
        flow_id="EXFIL-0",
        src_ip="10.70.70.70",
        src_port=43000,
        dst_ip="10.80.80.80",
        dst_port=443,
        protocol="tcp",
        service="ssl",
        duration=30.0,
        orig_bytes=2 * 1024 * 1024,
        resp_bytes=1024,
        orig_pkts=2000,
        resp_pkts=2,
        conn_state="SF",
        history="ShAd",
    )

    results.append(
        run_behavioral_test(
            "Exfiltration behavioral test",
            "EXFILTRATION",
            [exfil_flow],
        )
    )

    return results


def run_throughput_benchmark() -> dict[str, Any]:
    total_flows = 10_000
    engine = StreamingDetectionEngine(window_seconds=10.0)

    start = time.perf_counter()
    latencies = []

    base_ts = time.time()

    for i in range(total_flows):
        flow = make_flow(
            timestamp=base_ts + (i * 0.0001),
            flow_id=f"BENCH-{i}",
            src_ip=f"10.0.{(i // 254) % 254 + 1}.{i % 254 + 1}",
            src_port=10000 + (i % 50000),
            dst_ip="192.0.2.10",
            dst_port=443,
            service="ssl",
            duration=0.01,
            orig_bytes=500,
            resp_bytes=1200,
            orig_pkts=5,
            resp_pkts=6,
            conn_state="SF",
            history="ShADadF",
        )

        t0 = time.perf_counter()
        engine.process_flow(flow)
        latencies.append(
            (time.perf_counter() - t0) * 1000
        )

    elapsed = time.perf_counter() - start

    latencies.sort()

    p95 = latencies[
        max(
            0,
            int(len(latencies) * 0.95) - 1,
        )
    ]

    result = {
        "flows_processed": total_flows,
        "total_time_seconds": elapsed,
        "throughput_flows_per_second": (
            total_flows / elapsed
            if elapsed > 0
            else 0.0
        ),
        "average_latency_ms": statistics.mean(
            latencies
        ),
        "p95_latency_ms": p95,
        "dropped_flows": 0,
        "window_seconds": 10.0,
    }

    print()
    print("=" * 78)
    print("STREAMING ENGINE THROUGHPUT")
    print("=" * 78)
    print(
        f"Flows:       {result['flows_processed']}"
    )
    print(
        f"Throughput:  "
        f"{result['throughput_flows_per_second']:.2f} flows/sec"
    )
    print(
        f"Average:     "
        f"{result['average_latency_ms']:.3f} ms"
    )
    print(
        f"P95:         "
        f"{result['p95_latency_ms']:.3f} ms"
    )
    print(
        f"Dropped:     {result['dropped_flows']}"
    )

    return result


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    behavioral_results = run_behavioral_validation()

    throughput = run_throughput_benchmark()

    subprocess_results = []

    subprocess_results.append(
        run_command(
            "TLS REGRESSION TESTS",
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "training/test_tls_detector.py",
            ],
        )
    )

    subprocess_results.append(
        run_command(
            "REAL CIC-IDS2017 FLOW TEST",
            [
                sys.executable,
                "training/test_real_flows.py",
            ],
        )
    )

    subprocess_results.append(
        run_command(
            "DNS MODEL EVALUATION",
            [
                sys.executable,
                "training/test_dns_model.py",
            ],
        )
    )

    subprocess_results.append(
        run_command(
            "DNS BEHAVIORAL BENCHMARK",
            [
                sys.executable,
                "training/evaluate_dns_behavior.py",
            ],
        )
    )

    subprocess_results.append(
        run_command(
            "END-TO-END STREAMING TEST",
            [
                sys.executable,
                "training/test_stream.py",
            ],
        )
    )

    behavioral_pass = all(
        item["passed"]
        for item in behavioral_results
    )

    alert_schema_pass = all(
        item["alert_schema_valid"]
        for item in behavioral_results
        if item["passed"]
    )

    subprocess_pass = all(
        item["passed"]
        for item in subprocess_results
    )

    payload = {
        "project": "NETRA",
        "problem_statement": "SIH26145",
        "generated_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "behavioral_validation": behavioral_results,
        "throughput_benchmark": throughput,
        "existing_test_suite": subprocess_results,
        "summary": {
            "behavioral_detection_pass": behavioral_pass,
            "alert_schema_pass": alert_schema_pass,
            "existing_tests_pass": subprocess_pass,
            "overall_validated_components_pass": (
                behavioral_pass
                and alert_schema_pass
                and subprocess_pass
            ),
        },
    }

    OUTPUT_FILE.write_text(
        json.dumps(
            payload,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 78)
    print("SIH26145 FINAL VALIDATION SUMMARY")
    print("=" * 78)

    for item in behavioral_results:
        print(
            f"{'PASS' if item['passed'] else 'FAIL':6} "
            f"{item['name']}"
        )

    print(
        f"{'PASS' if alert_schema_pass else 'FAIL':6} "
        "Standardized behavioral alert schema"
    )

    for item in subprocess_results:
        print(
            f"{'PASS' if item['passed'] else 'FAIL':6} "
            f"{item['name']}"
        )

    overall = (
        behavioral_pass
        and alert_schema_pass
        and subprocess_pass
    )

    print()
    print(
        "Overall validated components:",
        "PASS" if overall else "CHECK FAILURES",
    )
    print("Saved:", OUTPUT_FILE)

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
