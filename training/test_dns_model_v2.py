from __future__ import annotations

import json
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd

from scipy.sparse import csr_matrix, hstack

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    fbeta_score,
    precision_score,
    recall_score,
)

from training.dns_model_features import (
    build_numeric_features,
)


TEST_PATH = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "dns_threats"
    / "test_combined_multiclass.csv.gz"
)

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "netra_dns_tunnel_model_v2.joblib"
)

THRESHOLD_PATH = (
    BASE_DIR
    / "models"
    / "netra_dns_tunnel_threshold_v2.json"
)

RESULT_PATH = (
    BASE_DIR
    / "models"
    / "netra_dns_evaluation_v2.json"
)


def main() -> None:
    print("Loading DNS Tunnel V2 model...")

    package = joblib.load(
        MODEL_PATH
    )

    classifier = package["classifier"]
    vectorizer = package["vectorizer"]
    scaler = package["scaler"]

    threshold_data = json.loads(
        THRESHOLD_PATH.read_text(
            encoding="utf-8"
        )
    )

    threshold = float(
        threshold_data[
            "selected_threshold"
        ]["threshold"]
    )

    print(
        f"Using calibrated threshold: {threshold:.2f}"
    )

    print()
    print(
        "Loading untouched official test set..."
    )

    df = pd.read_csv(
        TEST_PATH,
        compression="gzip",
        usecols=["domain", "class"],
    )

    df["domain"] = (
        df["domain"]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.rstrip(".")
    )

    df = df[
        df["domain"].str.len() > 0
    ].copy()

    # Remove exact duplicate domains for this
    # independent domain-level evaluation.
    df = df.drop_duplicates(
        subset=["domain", "class"]
    ).reset_index(drop=True)

    y_true = (
        df["class"] == 2
    ).astype(np.int8).to_numpy()

    print(
        "Evaluation rows after deduplication:",
        len(df),
    )

    print()
    print(
        "Original class distribution:"
    )

    print(
        df["class"].value_counts()
        .sort_index()
    )

    start = time.perf_counter()

    text_features = vectorizer.transform(
        df["domain"]
    )

    numeric = build_numeric_features(
        df["domain"]
    )

    numeric_scaled = (
        scaler.transform(
            numeric
        ).astype(np.float32)
    )

    matrix = hstack(
        [
            text_features,
            csr_matrix(
                numeric_scaled,
                dtype=np.float32,
            ),
        ],
        format="csr",
        dtype=np.float32,
    )

    probabilities = (
        classifier.predict_proba(
            matrix
        )[:, 1]
    )

    y_pred = (
        probabilities >= threshold
    ).astype(np.int8)

    elapsed = (
        time.perf_counter()
        - start
    )

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

    f1 = fbeta_score(
        y_true,
        y_pred,
        beta=1.0,
        zero_division=0,
    )

    f05 = fbeta_score(
        y_true,
        y_pred,
        beta=0.5,
        zero_division=0,
    )

    print()
    print("=" * 80)
    print("DNS TUNNEL V2 — INDEPENDENT TEST")
    print("=" * 80)

    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=[
                "NOT_TUNNEL",
                "DNS_TUNNEL",
            ],
            digits=4,
            zero_division=0,
        )
    )

    matrix_result = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    )

    print(
        "Confusion matrix:"
    )

    print(matrix_result)

    print()
    print(
        f"Tunnel precision: {precision:.4f}"
    )

    print(
        f"Tunnel recall:    {recall:.4f}"
    )

    print(
        f"Tunnel F1:        {f1:.4f}"
    )

    print(
        f"Tunnel F0.5:      {f05:.4f}"
    )

    print(
        f"Evaluation time:  {elapsed:.2f} sec"
    )

    print(
        "Evaluation throughput:",
        f"{len(df) / elapsed:.2f} domains/sec"
    )

    result = {
        "model_version": "DNS_TUNNEL_V2",
        "threshold": threshold,
        "test_rows": int(len(df)),
        "tunnel_precision": float(
            precision
        ),
        "tunnel_recall": float(
            recall
        ),
        "tunnel_f1": float(
            f1
        ),
        "tunnel_f0_5": float(
            f05
        ),
        "confusion_matrix": (
            matrix_result.tolist()
        ),
        "evaluation_seconds": elapsed,
        "evaluation_domains_per_second": (
            len(df) / elapsed
            if elapsed > 0
            else 0.0
        ),
    }

    RESULT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    print()
    print(
        "Saved:",
        RESULT_PATH,
    )


if __name__ == "__main__":
    main()
