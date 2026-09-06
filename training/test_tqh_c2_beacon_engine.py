from __future__ import annotations

import json
from pathlib import Path

from app.services.tls.tls_c2_beacon import TLSC2BeaconEngine


ROOT = Path(__file__).resolve().parents[1]

DATASET = (
    ROOT
    / "datasets/raw/tqh_c2/extracted_labels/"
    / "A/A_i30_j0/labeled.jsonl"
)


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

            # TLS-observable traffic only.
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


def main():
    rows = load_rows()

    engine = TLSC2BeaconEngine(
        window_seconds=180.0,
        minimum_events=4,
        max_cv=0.20,
        min_interval=5.0,
        max_interval=60.0,
    )

    results = []

    for row in rows:
        fields = {
            "ts": str(row["ts"]),
            "id.orig_h": str(row["orig_h"]),
            "id.resp_h": str(row["resp_h"]),
            "ja4": str(row["ja4"]),
            "ja4s": str(row["ja4s"]),
        }

        detection = engine.analyze(fields)

        results.append(
            {
                "uid": row["uid"],
                "label": row["label"],
                "triggered": detection.triggered,
                "score": detection.score,
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
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if fp + tn
        else 0.0
    )

    print("========================================")
    print("NETRA TLS C2 BEACON ENGINE VALIDATION")
    print("========================================")
    print(f"TLS-observable rows: {len(rows)}")

    print("\n------------ RESULTS ------------")
    print(f"TP:  {tp}")
    print(f"FN:  {fn}")
    print(f"FP:  {fp}")
    print(f"TN:  {tn}")
    print()
    print(f"Precision:           {precision:.4f}")
    print(f"Recall:              {recall:.4f}")
    print(f"F1:                  {f1:.4f}")
    print(f"False-positive rate: {fpr:.4f}")

    print("\n------------ FIRST MALICIOUS TRIGGERS ------------")

    count = 0

    for r in results:
        if r["label"] == "malicious_c2" and r["triggered"]:
            e = r["evidence"]

            print(
                f"uid={r['uid']} "
                f"score={r['score']:.2f} "
                f"events={e.get('event_count')} "
                f"interval={e.get('average_interval_seconds')}s "
                f"CV={e.get('coefficient_of_variation')}"
            )

            count += 1

            if count >= 10:
                break


if __name__ == "__main__":
    main()
