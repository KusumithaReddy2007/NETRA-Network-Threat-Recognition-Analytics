from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Make the NETRA project root importable when this file is run directly.
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
    f1_score,
    precision_score,
    recall_score,
)

from backend.app.services.dns.dns_features import extract_dns_features


TEST_PATH = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "dns_threats"
    / "test_combined_multiclass.csv.gz"
)

MODEL_PATH = BASE_DIR / "models" / "netra_dns_model.joblib"
RESULT_PATH = BASE_DIR / "models" / "netra_dns_evaluation.json"


def build_numeric_features(domains: pd.Series) -> np.ndarray:
    rows = []

    for domain in domains:
        features = extract_dns_features(domain)

        rows.append(
            [
                features.query_length,
                features.label_count,
                features.longest_label_length,
                features.subdomain_depth,
                features.digit_ratio,
                features.unique_char_ratio,
                features.entropy,
                features.vowel_ratio,
                features.hyphen_ratio,
                features.underscore_ratio,
                features.numeric_label_count,
                features.max_label_entropy,
                float(features.suspicious_tld),
            ]
        )

    return np.asarray(rows, dtype=np.float32)


def main() -> None:
    print("Loading DNS model...")

    package = joblib.load(MODEL_PATH)

    classifier = package["classifier"]
    vectorizer = package["vectorizer"]
    scaler = package["scaler"]

    print("Loading official test set...")

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

    df = df[df["domain"].str.len() > 0].copy()

    domains = df["domain"]
    y_true = df["class"].to_numpy(dtype=np.int64)

    print("Test rows:", len(df))
    print("Test distribution:")
    print(pd.Series(y_true).value_counts().sort_index())

    start = time.perf_counter()

    text_features = vectorizer.transform(domains)

    numeric = build_numeric_features(domains)
    numeric_scaled = scaler.transform(numeric).astype(np.float32)

    numeric_sparse = csr_matrix(
        numeric_scaled,
        dtype=np.float32,
    )

    combined = hstack(
        [
            text_features,
            numeric_sparse,
        ],
        format="csr",
        dtype=np.float32,
    )

    y_pred = classifier.predict(combined)
    probabilities = classifier.predict_proba(combined)

    elapsed = time.perf_counter() - start

    labels = [0, 1, 2]
    names = ["BENIGN", "DGA", "DNS_TUNNEL"]

    print()
    print("=" * 80)
    print("DNS MODEL EVALUATION")
    print("=" * 80)

    print(
        classification_report(
            y_true,
            y_pred,
            labels=labels,
            target_names=names,
            digits=4,
            zero_division=0,
        )
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=labels,
    )

    print("Confusion matrix:")
    print(matrix)

    macro_f1 = f1_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0,
    )

    macro_precision = precision_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    macro_recall = recall_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0,
    )

    tunnel_precision = precision_score(
        y_true,
        y_pred,
        labels=[2],
        average="macro",
        zero_division=0,
    )

    tunnel_recall = recall_score(
        y_true,
        y_pred,
        labels=[2],
        average="macro",
        zero_division=0,
    )

    tunnel_f1 = f1_score(
        y_true,
        y_pred,
        labels=[2],
        average="macro",
        zero_division=0,
    )

    mean_confidence = float(
        np.mean(np.max(probabilities, axis=1))
    )

    throughput = (
        len(df) / elapsed
        if elapsed > 0
        else 0.0
    )

    metrics = {
        "test_rows": int(len(df)),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "dns_tunnel_precision": float(tunnel_precision),
        "dns_tunnel_recall": float(tunnel_recall),
        "dns_tunnel_f1": float(tunnel_f1),
        "mean_prediction_confidence": mean_confidence,
        "evaluation_seconds": elapsed,
        "evaluation_rows_per_second": throughput,
        "confusion_matrix": matrix.tolist(),
        "class_names": names,
    }

    RESULT_PATH.write_text(
        json.dumps(metrics, indent=2),
        encoding="utf-8",
    )

    print("=" * 80)
    print(f"Macro F1:              {macro_f1:.4f}")
    print(f"Weighted F1:           {weighted_f1:.4f}")
    print(f"Macro precision:       {macro_precision:.4f}")
    print(f"Macro recall:          {macro_recall:.4f}")
    print(f"DNS tunnel precision:  {tunnel_precision:.4f}")
    print(f"DNS tunnel recall:     {tunnel_recall:.4f}")
    print(f"DNS tunnel F1:         {tunnel_f1:.4f}")
    print(f"Mean confidence:       {mean_confidence:.4f}")
    print(f"Evaluation throughput: {throughput:.2f} domains/sec")
    print(f"Evaluation time:       {elapsed:.2f} sec")
    print()
    print("Saved:", RESULT_PATH)


if __name__ == "__main__":
    main()
