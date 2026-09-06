from __future__ import annotations

import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np

from sklearn.metrics import (
    f1_score,
    fbeta_score,
    precision_score,
    recall_score,
)


MODEL_DIR = BASE_DIR / "models"

VALIDATION_PATH = (
    MODEL_DIR
    / "dns_tunnel_v2_validation.npz"
)

OUTPUT_PATH = (
    MODEL_DIR
    / "netra_dns_tunnel_threshold_v2.json"
)


def main() -> None:
    data = np.load(
        VALIDATION_PATH
    )

    y_true = data["y_true"]
    probabilities = data["probability"]

    best = None

    rows = []

    # Search the useful operational range.
    thresholds = np.arange(
        0.50,
        1.001,
        0.01,
    )

    for threshold in thresholds:
        y_pred = (
            probabilities >= threshold
        ).astype(np.int8)

        precision = precision_score(
            y_true,
            y_pred,
            zero_division=0,
        )

        recall = recall_score(
            y_true,
            y_pred,
            zero_division=0,
        )

        f1 = f1_score(
            y_true,
            y_pred,
            zero_division=0,
        )

        f05 = fbeta_score(
            y_true,
            y_pred,
            beta=0.5,
            zero_division=0,
        )

        row = {
            "threshold": float(
                round(threshold, 2)
            ),
            "precision": float(
                precision
            ),
            "recall": float(
                recall
            ),
            "f1": float(f1),
            "f0_5": float(f05),
        }

        rows.append(row)

        if (
            best is None
            or row["f0_5"] > best["f0_5"]
        ):
            best = row

    assert best is not None

    result = {
        "model_version": "DNS_TUNNEL_V2",
        "selection_metric": "F0.5",
        "selected_threshold": best,
        "search_results": rows,
    }

    OUTPUT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("=" * 80)
    print("DNS TUNNEL V2 THRESHOLD CALIBRATION")
    print("=" * 80)

    print(
        f"Selected threshold: {best['threshold']:.2f}"
    )

    print(
        f"Validation precision: {best['precision']:.4f}"
    )

    print(
        f"Validation recall:    {best['recall']:.4f}"
    )

    print(
        f"Validation F1:        {best['f1']:.4f}"
    )

    print(
        f"Validation F0.5:      {best['f0_5']:.4f}"
    )

    print()
    print(
        "Saved:",
        OUTPUT_PATH,
    )


if __name__ == "__main__":
    main()
