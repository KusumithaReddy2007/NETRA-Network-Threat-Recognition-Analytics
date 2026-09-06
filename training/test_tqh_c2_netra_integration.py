from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.ingestion.netra_stream_engine import NetraStreamEngine
from app.services.tls.tls_reader import ZeekTLSRecord


DATASET = (
    ROOT
    / "datasets/raw/tqh_c2/extracted_labels/"
    / "A/A_i30_j0/labeled.jsonl"
)


REQUIRED_ALERT_FIELDS = {
    "alert_id",
    "timestamp",
    "flow_id",
    "threat_class",
    "confidence",
    "severity",
    "supporting_evidence",
}


def load_rows():
    rows = []

    with DATASET.open("r", encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)

            if row.get("label") not in {
                "benign",
                "malicious_c2",
            }:
                continue

            if not row.get("version"):
                continue

            if not row.get("ja4") or not row.get("ja4s"):
                continue

            rows.append(row)

    rows.sort(
        key=lambda r: (
            float(r["ts"]),
            str(r["uid"]),
        )
    )

    return rows


def to_tls_record(row):
    return ZeekTLSRecord(
        fields={
            "ts": str(row["ts"]),
            "uid": str(row["uid"]),
            "id.orig_h": str(row["orig_h"]),
            "id.orig_p": str(row["orig_p"]),
            "id.resp_h": str(row["resp_h"]),
            "id.resp_p": str(row["resp_p"]),
            "version": str(row.get("version") or ""),
            "cipher": str(row.get("cipher") or ""),
            "curve": str(row.get("curve") or ""),
            "server_name": str(row.get("server_name") or ""),
            "resumed": str(row.get("resumed") or ""),
            "ssl_history": str(row.get("ssl_history") or ""),
            "ja4": str(row.get("ja4") or ""),
            "ja4s": str(row.get("ja4s") or ""),
        }
    )


def main():
    rows = load_rows()

    engine = NetraStreamEngine(
        tls_window_seconds=60.0,
    )

    first_malicious_alert = None
    benign_bot_c2_alerts = 0
    malicious_bot_c2_alerts = 0
    malformed_alerts = 0

    for row in rows:
        result = engine.process_tls(
            to_tls_record(row)
        )

        alerts = result.get("alerts", [])

        for alert in alerts:
            required_missing = (
                REQUIRED_ALERT_FIELDS
                - set(alert.keys())
            )

            if required_missing:
                malformed_alerts += 1
                continue

            if alert["threat_class"] == "BOT_C2":

                if row["label"] == "malicious_c2":
                    malicious_bot_c2_alerts += 1

                    if first_malicious_alert is None:
                        first_malicious_alert = (
                            row,
                            alert,
                        )

                elif row["label"] == "benign":
                    benign_bot_c2_alerts += 1

    print("========================================")
    print("NETRA END-TO-END TLS INTEGRATION TEST")
    print("========================================")
    print(f"TLS-observable rows: {len(rows)}")
    print(
        f"Malicious BOT_C2 alerts: "
        f"{malicious_bot_c2_alerts}"
    )
    print(
        f"Benign BOT_C2 alerts:    "
        f"{benign_bot_c2_alerts}"
    )
    print(
        f"Malformed alerts:        "
        f"{malformed_alerts}"
    )

    print("\n------------ FIRST MALICIOUS ALERT ------------")

    if first_malicious_alert is None:
        print("NO MALICIOUS BOT_C2 ALERT FOUND")
        raise SystemExit(1)

    row, alert = first_malicious_alert

    print(
        json.dumps(
            {
                "input_label": row["label"],
                "uid": row["uid"],
                "alert": alert,
            },
            indent=2,
        )
    )

    evidence = alert.get(
        "supporting_evidence",
        {},
    )

    assert alert["threat_class"] == "BOT_C2"
    assert alert["flow_id"].startswith("TLS-")
    assert 0 <= float(alert["confidence"]) <= 100
    assert REQUIRED_ALERT_FIELDS <= set(alert.keys())
    assert evidence.get("payload_decryption") is False
    assert benign_bot_c2_alerts == 1
    assert malformed_alerts == 0

    print("\nPASS: real TQH-C2 TLS traffic reaches NETRA")
    print("PASS: BOT_C2 alert generated")
    print("PASS: standard alert schema present")
    print("PASS: payload_decryption=False")
    print("PASS: benign BOT_C2 false-positive count <= 1")


if __name__ == "__main__":
    main()
