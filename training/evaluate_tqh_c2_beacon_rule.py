from __future__ import annotations

import json
from collections import defaultdict
from statistics import mean, pstdev
from pathlib import Path

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
            r = json.loads(line)

            if r.get("label") not in {
                "benign",
                "malicious_c2",
            }:
                continue

            # Only TLS-observable flows.
            if not r.get("version"):
                continue

            if not r.get("ja4"):
                continue

            if not r.get("ja4s"):
                continue

            rows.append(r)

    rows.sort(
        key=lambda r: (
            float(r["ts"]),
            str(r["uid"]),
        )
    )

    return rows


def detect(rows):
    """
    Experimental encrypted-C2 beacon rule.

    A source is considered suspicious when, within a rolling
    180-second window, it produces >=4 TLS events to the same
    destination using the same JA4/JA4S fingerprint with
    regular inter-arrival timing.

    This is an experiment only; it does not modify NETRA.
    """

    window = 180.0
    minimum_events = 4
    max_cv = 0.20
    min_interval = 5.0
    max_interval = 60.0

    queues = defaultdict(list)
    results = []

    for row in rows:
        ts = float(row["ts"])

        key = (
            row["orig_h"],
            row["resp_h"],
            row.get("ja4"),
            row.get("ja4s"),
        )

        q = queues[key]
        q.append(ts)

        cutoff = ts - window
        while q and q[0] < cutoff:
            q.pop(0)

        triggered = False
        cv = None
        avg_interval = None

        if len(q) >= minimum_events:
            intervals = [
                b - a
                for a, b in zip(q, q[1:])
                if b > a
            ]

            if len(intervals) >= 3:
                avg_interval = mean(intervals)

                if avg_interval > 0:
                    cv = pstdev(intervals) / avg_interval

                    triggered = (
                        min_interval
                        <= avg_interval
                        <= max_interval
                        and cv <= max_cv
                    )

        results.append(
            {
                "label": row["label"],
                "triggered": triggered,
                "cv": cv,
                "avg_interval": avg_interval,
                "source": row["orig_h"],
                "destination": row["resp_h"],
                "ja4": row.get("ja4"),
                "ja4s": row.get("ja4s"),
                "uid": row["uid"],
            }
        )

    return results


def main():
    rows = load_rows()
    results = detect(rows)

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
    print("TQH-C2 EXPERIMENTAL C2 BEACON RULE")
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

    print("\n------------ TRIGGER EXAMPLES ------------")

    shown = 0

    for r in results:
        if r["triggered"] and r["label"] == "malicious_c2":
            print(
                f"label={r['label']} "
                f"uid={r['uid']} "
                f"src={r['source']} "
                f"dst={r['destination']} "
                f"interval={r['avg_interval']:.3f}s "
                f"CV={r['cv']:.4f}"
            )

            shown += 1

            if shown >= 10:
                break


if __name__ == "__main__":
    main()
