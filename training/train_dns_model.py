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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from backend.app.services.dns.dns_features import extract_dns_features


TRAIN_PATH = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "dns_threats"
    / "train_combined_multiclass.csv.gz"
)

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "netra_dns_model.joblib"
META_PATH = MODEL_DIR / "netra_dns_model_metadata.json"

RANDOM_STATE = 42

MAX_BENIGN = 300_000
MAX_DGA = 300_000
MAX_TUNNEL = 6_441

CHAR_NGRAM_RANGE = (2, 5)
MAX_TFIDF_FEATURES = 50_000


def load_training_data() -> pd.DataFrame:
    print(f"Loading: {TRAIN_PATH}")

    df = pd.read_csv(
        TRAIN_PATH,
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

    samples = []

    for label, limit in [
        (0, MAX_BENIGN),
        (1, MAX_DGA),
        (2, MAX_TUNNEL),
    ]:
        subset = df[df["class"] == label]

        if len(subset) > limit:
            subset = subset.sample(
                n=limit,
                random_state=RANDOM_STATE,
            )

        samples.append(subset)

    result = pd.concat(
        samples,
        ignore_index=True,
    )

    result = result.sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    return result


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
    start = time.perf_counter()

    df = load_training_data()

    print()
    print("Training shape:", df.shape)
    print("Training distribution:")
    print(df["class"].value_counts().sort_index())

    domains = df["domain"]
    labels = df["class"].to_numpy(dtype=np.int64)

    print()
    print("Building character n-gram features...")

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=CHAR_NGRAM_RANGE,
        max_features=MAX_TFIDF_FEATURES,
        lowercase=True,
        sublinear_tf=True,
        dtype=np.float32,
    )

    text_features = vectorizer.fit_transform(domains)

    print("TF-IDF shape:", text_features.shape)

    print("Building DNS numeric features...")

    numeric = build_numeric_features(domains)

    scaler = StandardScaler()
    numeric_scaled = scaler.fit_transform(numeric).astype(np.float32)

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

    print("Combined feature matrix:", combined.shape)

    print()
    print("Training Logistic Regression classifier...")

    classifier = LogisticRegression(
        solver="saga",
        max_iter=100,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        C=4.0,
    )

    classifier.fit(combined, labels)

    elapsed = time.perf_counter() - start

    package = {
        "classifier": classifier,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "numeric_feature_names": [
            "query_length",
            "label_count",
            "longest_label_length",
            "subdomain_depth",
            "digit_ratio",
            "unique_char_ratio",
            "entropy",
            "vowel_ratio",
            "hyphen_ratio",
            "underscore_ratio",
            "numeric_label_count",
            "max_label_entropy",
            "suspicious_tld",
        ],
        "class_names": {
            0: "BENIGN",
            1: "DGA",
            2: "DNS_TUNNEL",
        },
    }

    print()
    print(f"Saving model: {MODEL_PATH}")

    joblib.dump(
        package,
        MODEL_PATH,
        compress=3,
    )

    metadata = {
        "model": "LogisticRegression + character TF-IDF + DNS numeric features",
        "training_dataset": "CVUT DNS Threats Dataset",
        "random_state": RANDOM_STATE,
        "training_rows": int(len(df)),
        "class_distribution": {
            str(k): int(v)
            for k, v in df["class"].value_counts().sort_index().items()
        },
        "char_ngram_range": CHAR_NGRAM_RANGE,
        "max_tfidf_features": MAX_TFIDF_FEATURES,
        "class_names": {
            "0": "BENIGN",
            "1": "DGA",
            "2": "DNS_TUNNEL",
        },
        "training_time_seconds": round(elapsed, 3),
    }

    META_PATH.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print()
    print("DNS model training complete.")
    print("Model:", MODEL_PATH)
    print("Metadata:", META_PATH)
    print(f"Training time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
