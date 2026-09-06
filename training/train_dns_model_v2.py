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

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


from dns_model_features import (
    NUMERIC_FEATURE_NAMES,
    build_numeric_features,
)


TRAIN_PATH = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "dns_threats"
    / "train_combined_multiclass.csv.gz"
)

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

MODEL_PATH = (
    MODEL_DIR
    / "netra_dns_tunnel_model_v2.joblib"
)

META_PATH = (
    MODEL_DIR
    / "netra_dns_tunnel_model_v2_metadata.json"
)

RANDOM_STATE = 42

TRAIN_BENIGN = 200_000
TRAIN_DGA = 200_000

CHAR_NGRAM_RANGE = (2, 6)
MAX_TFIDF_FEATURES = 75_000


def load_and_prepare() -> pd.DataFrame:
    print("Loading original DNS training data...")

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

    df = df[
        df["domain"].str.len() > 0
    ].copy()

    print(
        "Rows before deduplication:",
        len(df),
    )

    df = df.drop_duplicates(
        subset=["domain", "class"]
    ).reset_index(drop=True)

    print(
        "Rows after deduplication:",
        len(df),
    )

    tunnel = df[
        df["class"] == 2
    ]

    benign = df[
        df["class"] == 0
    ]

    dga = df[
        df["class"] == 1
    ]

    if len(tunnel) == 0:
        raise RuntimeError(
            "No DNS tunnelling samples found."
        )

    if len(benign) > TRAIN_BENIGN:
        benign = benign.sample(
            n=TRAIN_BENIGN,
            random_state=RANDOM_STATE,
        )

    if len(dga) > TRAIN_DGA:
        dga = dga.sample(
            n=TRAIN_DGA,
            random_state=RANDOM_STATE,
        )

    selected = pd.concat(
        [
            benign,
            dga,
            tunnel,
        ],
        ignore_index=True,
    )

    # Binary target:
    # 0 = benign/DGA
    # 1 = DNS tunnelling
    selected["target"] = (
        selected["class"] == 2
    ).astype(np.int8)

    selected = selected.sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    return selected


def main() -> None:
    start = time.perf_counter()

    df = load_and_prepare()

    print()
    print(
        "Training distribution:"
    )
    print(
        df["target"].value_counts()
    )

    # Create a validation subset from the selected development data.
    # This validation data is NOT the official test set.
    train_df, validation_df = train_test_split(
        df,
        test_size=0.15,
        random_state=RANDOM_STATE,
        stratify=df["target"],
    )

    print()
    print(
        "Development training rows:",
        len(train_df),
    )

    print(
        "Validation rows:",
        len(validation_df),
    )

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=CHAR_NGRAM_RANGE,
        max_features=MAX_TFIDF_FEATURES,
        lowercase=True,
        sublinear_tf=True,
        dtype=np.float32,
    )

    print()
    print("Building character n-grams...")

    text_train = vectorizer.fit_transform(
        train_df["domain"]
    )

    text_validation = vectorizer.transform(
        validation_df["domain"]
    )

    print(
        "Text matrix:",
        text_train.shape,
    )

    print("Building numeric DNS features...")

    numeric_train = build_numeric_features(
        train_df["domain"]
    )

    numeric_validation = build_numeric_features(
        validation_df["domain"]
    )

    scaler = StandardScaler()

    numeric_train_scaled = (
        scaler.fit_transform(
            numeric_train
        ).astype(np.float32)
    )

    numeric_validation_scaled = (
        scaler.transform(
            numeric_validation
        ).astype(np.float32)
    )

    train_matrix = hstack(
        [
            text_train,
            csr_matrix(
                numeric_train_scaled,
                dtype=np.float32,
            ),
        ],
        format="csr",
        dtype=np.float32,
    )

    validation_matrix = hstack(
        [
            text_validation,
            csr_matrix(
                numeric_validation_scaled,
                dtype=np.float32,
            ),
        ],
        format="csr",
        dtype=np.float32,
    )

    y_train = train_df["target"].to_numpy(
        dtype=np.int8
    )

    y_validation = validation_df["target"].to_numpy(
        dtype=np.int8
    )

    print(
        "Combined train matrix:",
        train_matrix.shape,
    )

    print()
    print(
        "Training binary DNS tunnelling model..."
    )

    classifier = LogisticRegression(
        solver="saga",
        max_iter=500,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        C=2.0,
    )

    classifier.fit(
        train_matrix,
        y_train,
    )

    validation_probability = (
        classifier.predict_proba(
            validation_matrix
        )[:, 1]
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    package = {
        "classifier": classifier,
        "vectorizer": vectorizer,
        "scaler": scaler,
        "numeric_feature_names": (
            NUMERIC_FEATURE_NAMES
        ),
        "positive_class": "DNS_TUNNEL",
        "negative_class": "NOT_TUNNEL",
    }

    joblib.dump(
        package,
        MODEL_PATH,
        compress=3,
    )

    metadata = {
        "model_version": "DNS_TUNNEL_V2",
        "model": (
            "Binary Logistic Regression + "
            "character TF-IDF + DNS statistical features"
        ),
        "dataset": (
            "CVUT DNS Threats Dataset"
        ),
        "deduplicated": True,
        "random_state": RANDOM_STATE,
        "train_rows": int(len(train_df)),
        "validation_rows": int(
            len(validation_df)
        ),
        "training_distribution": {
            str(k): int(v)
            for k, v in df[
                "target"
            ].value_counts().items()
        },
        "char_ngram_range": (
            CHAR_NGRAM_RANGE
        ),
        "max_tfidf_features": (
            MAX_TFIDF_FEATURES
        ),
        "numeric_features": (
            NUMERIC_FEATURE_NAMES
        ),
        "training_time_seconds": round(
            elapsed,
            3,
        ),
    }

    META_PATH.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    # Save validation probabilities for the threshold calibration step.
    validation_output = (
        MODEL_DIR
        / "dns_tunnel_v2_validation.npz"
    )

    np.savez_compressed(
        validation_output,
        y_true=y_validation,
        probability=validation_probability,
    )

    print()
    print(
        "DNS TUNNEL V2 training complete."
    )
    print(
        "Model:",
        MODEL_PATH,
    )
    print(
        "Metadata:",
        META_PATH,
    )
    print(
        "Validation data:",
        validation_output,
    )
    print(
        f"Training time: {elapsed:.2f} seconds"
    )


if __name__ == "__main__":
    main()
