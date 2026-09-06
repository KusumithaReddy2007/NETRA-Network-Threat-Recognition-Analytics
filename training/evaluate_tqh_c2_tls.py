from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow imports from backend/
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.tls.tls_detector import TLSBehaviorEngine
from app.services.tls.tls_reader import ZeekTLSRecord


DATASET = (
    ROOT
    / "datasets"
    / "raw"
    / "tqh_c2"
    / "extracted_labels"
    / "A"
    / "A_i30_j0"
    / "labeled.jsonl"
)

OUTPUT = (
    ROOT
    / "docs"
    / "SIH26145_TQHC2_TLS_VALIDATION.json"
)


def load_rows() -> list[dict]:
    rows = []

    with DATASET.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            row = json.loads(line)

            if row.get("label") not in {
                "benign",
                "malicious_c2",
            }:
                continue

            # We only evaluate rows having TLS metadata.
            # A row with no TLS metadata cannot be evaluated
            # by the TLS metadata detector.
            if not row.get("version"):
                continue

            rows.append(row)

    rows.sort(
        key=lambda r: (
            float(r.get("ts", 0.0)),
            str(r.get("uid", "")),
        )
    )

    return rows


def make_zeek_tls_record(row: dict) -> ZeekTLSRecord:
    fields = {
        "ts": str(row.get("ts", "")),
        "uid": str(row.get("uid", "")),
        "id.orig_h": str(row.get("orig_h", "")),
        "id.orig_p": str(row.get("orig_p", "")),
        "id.resp_h": str(row.get("resp_h", "")),
        "id.resp_p": str(row.get("resp_p", "")),
        "version": str(row.get("version") or ""),
        "cipher": str(row.get("cipher") or ""),
        "curve": str(row.get("curve") or ""),
        "server_name": str(row.get("server_name") or ""),
        "resumed": str(row.get("resumed") or ""),
        "ssl_history": str(row.get("ssl_history") or ""),
        "ja4": str(row.get("ja4") or ""),
        "ja4s": str(row.get("ja4s") or ""),
    }

    return ZeekTLSRecord(fields=fields)


def main() -> None:
    rows = load_rows()

    print("========================================")
    print("NETRA TQH-C2 TLS EXTERNAL VALIDATION")
    print("========================================")
    print(f"Dataset: {DATASET}")
    print(f"Evaluated TLS rows: {len(rows)}")

    if not rows:
        raise RuntimeError(
            "No TLS-observable rows found."
        )

    malicious = sum(
        r["label"] == "malicious_c2"
        for r in rows
    )

    benign = sum(
        r["label"] == "benign"
        for r in rows
    )

    print(f"Malicious C2 TLS rows: {malicious}")
    print(f"Benign TLS rows:       {benign}")

    engine = TLSBehaviorEngine(
        window_seconds=60.0,
        minimum_events=3,
        score_threshold=70.0,
        minimum_supporting_signals=3,
    )

    results = []

    for row in rows:
        detection = engine.analyze(
            make_zeek_tls_record(row)
        )

        results.append(
            {
                "uid": row.get("uid"),
                "timestamp": row.get("ts"),
                "source": row.get("orig_h"),
                "destination": row.get("resp_h"),
                "label": row.get("label"),
                "triggered": bool(
                    detection.triggered
                ),
                "score": float(
                    detection.score
                ),
                "threat_class": detection.threat_class,
                "evidence": detection.evidence,
            }
        )

    tp = sum(
        r["label"] == "malicious_c2"
        and r["triggered"]
        for r in results
    )

    fn = sum(
        r["label"] == "malicious_c2"
        and not r["triggered"]
        for r in results
    )

    fp = sum(
        r["label"] == "benign"
        and r["triggered"]
        for r in results
    )

    tn = sum(
        r["label"] == "benign"
        and not r["triggered"]
        for r in results
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0.0
    )

    malicious_detection_rate = (
        (tp / malicious)
        if malicious
        else 0.0
    )

    print()
    print("------------ RESULTS ------------")
    print(f"TP:  {tp}")
    print(f"FN:  {fn}")
    print(f"FP:  {fp}")
    print(f"TN:  {tn}")
    print()
    print(f"Precision:              {precision:.4f}")
    print(f"Recall:                 {recall:.4f}")
    print(f"F1:                     {f1:.4f}")
    print(f"False-positive rate:    {fpr:.4f}")
    print(
        "TLS malicious detection: "
        f"{malicious_detection_rate:.4f}"
    )

    triggered_malicious = [
        r for r in results
        if r["label"] == "malicious_c2"
        and r["triggered"]
    ]

    triggered_benign = [
        r for r in results
        if r["label"] == "benign"
        and r["triggered"]
    ]

    output = {
        "dataset": "TQH-C2",
        "version": "1.0.0",
        "source": "TQH-C2 A_i30_j0 labeled.jsonl",
        "profile": "A",
        "encryption": "TLS",
        "evaluation": {
            "rows_total_tls_observable": len(rows),
            "malicious_c2_tls_rows": malicious,
            "benign_tls_rows": benign,
            "tp": tp,
            "fn": fn,
            "fp": fp,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": fpr,
            "malicious_detection_rate_over_tls_rows":
                malicious_detection_rate,
        },
        "detector": {
            "window_seconds": 60.0,
            "minimum_events": 3,
            "score_threshold": 70.0,
            "minimum_supporting_signals": 3,
            "payload_decryption": False,
            "ja4_standalone_trigger": False,
        },
        "coverage_note": (
            "Only rows containing TLS metadata were evaluated. "
            "malicious_c2 rows without TLS metadata were excluded "
            "because the TLS metadata detector cannot observe them."
        ),
        "examples": {
            "malicious_triggered": triggered_malicious[:10],
            "benign_triggered": triggered_benign[:10],
        },
    }

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        json.dumps(
            output,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(f"Saved: {OUTPUT}")


if __name__ == "__main__":
    main()
