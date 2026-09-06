from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler


BASE_DIR = Path(__file__).resolve().parents[1]

RAW_DIR = (
    BASE_DIR
    / "datasets"
    / "raw"
    / "MachineLearningCVE"
)

OUTPUT_DIR = (
    BASE_DIR
    / "models"
)

MODEL_PATH = (
    OUTPUT_DIR
    / "netra_cicids_holdout_model.joblib"
)

ENCODER_PATH = (
    OUTPUT_DIR
    / "netra_cicids_holdout_label_encoder.joblib"
)

RESULT_PATH = (
    OUTPUT_DIR
    / "netra_cicids_holdout_evaluation.json"
)


FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Active Mean",
    "Idle Mean",
]

RANDOM_STATE = 42

TEST_SIZE = 0.20

# Keep the experiment computationally manageable.
MAX_TRAIN_PER_CLASS = 40_000
MAX_TEST_PER_CLASS = 10_000


def map_label(label: object) -> str | None:
    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    if label == "DDoS":
        return "DDOS"

    if label == "PortScan":
        return "PORTSCAN"

    if label == "Bot":
        return "BOT"

    if label in {
        "FTP-Patator",
        "SSH-Patator",
    }:
        return "BRUTE_FORCE"

    if label in {
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
    }:
        return "DOS"

    if "Web Attack" in label:
        return "WEB_ATTACK"

    return None


def load_file(path: Path) -> pd.DataFrame:
    """
    Load one original CICIDS file.

    The CICIDS files use headers with leading spaces, so headers
    are normalized immediately.
    """

    print(f"\nReading: {path.name}")

    df = pd.read_csv(
        path,
        usecols=lambda c: (
            c.strip() in FEATURES
            or c.strip() == "Label"
        ),
        low_memory=False,
    )

    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    missing = [
        column
        for column in FEATURES + ["Label"]
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"{path.name} is missing columns: {missing}"
        )

    df = df[
        FEATURES + ["Label"]
    ].copy()

    df["Threat Class"] = (
        df["Label"].map(map_label)
    )

    df = df.dropna(
        subset=["Threat Class"]
    )

    df = df.drop(
        columns=["Label"]
    )

    # Convert features to numeric.
    for column in FEATURES:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce",
        )

    df = df.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    df = df.dropna(
        subset=FEATURES
    )

    # Remove exact duplicates within the source file.
    before = len(df)

    df = df.drop_duplicates(
        subset=FEATURES + ["Threat Class"]
    ).reset_index(drop=True)

    print(
        f"Rows after cleaning/dedup: {len(df)} "
        f"(removed {before - len(df)})"
    )

    return df


def split_source_file(
    df: pd.DataFrame,
    source_name: str,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Split one original capture file into train/test.

    The source identity is preserved for reporting only.
    """

    df = df.copy()

    if df["Threat Class"].nunique() >= 2:
        train_df, test_df = train_test_split(
            df,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=df["Threat Class"],
        )
    else:
        train_df, test_df = train_test_split(
            df,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
        )

    train_df = train_df.copy()
    test_df = test_df.copy()

    train_df["Source File"] = source_name
    test_df["Source File"] = source_name

    return train_df, test_df


def cap_class_size(
    df: pd.DataFrame,
    max_per_class: int,
) -> pd.DataFrame:
    """
    Deterministically cap every class so the experiment remains
    practical while retaining all classes.
    """

    parts = []

    for threat_class in sorted(
        df["Threat Class"].unique()
    ):
        class_df = df[
            df["Threat Class"] == threat_class
        ]

        n = min(
            len(class_df),
            max_per_class,
        )

        class_df = class_df.sample(
            n=n,
            random_state=RANDOM_STATE,
        )

        parts.append(class_df)

    result = pd.concat(
        parts,
        ignore_index=True,
    )

    return result.sample(
        frac=1.0,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)


def main() -> None:
    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    source_files = sorted(
        RAW_DIR.glob("*.csv")
    )

    if not source_files:
        raise RuntimeError(
            f"No CICIDS CSV files found in {RAW_DIR}"
        )

    print("=" * 90)
    print("NETRA CICIDS HOLDOUT VALIDATION")
    print("=" * 90)

    print(
        f"Source files found: {len(source_files)}"
    )

    train_parts = []
    test_parts = []

    source_summary = {}

    for path in source_files:
        df = load_file(path)

        train_df, test_df = split_source_file(
            df,
            path.name,
        )

        train_parts.append(train_df)
        test_parts.append(test_df)

        source_summary[path.name] = {
            "total_rows": int(len(df)),
            "train_rows": int(len(train_df)),
            "test_rows": int(len(test_df)),
            "train_classes": {
                str(k): int(v)
                for k, v in train_df[
                    "Threat Class"
                ].value_counts().items()
            },
            "test_classes": {
                str(k): int(v)
                for k, v in test_df[
                    "Threat Class"
                ].value_counts().items()
            },
        }

    train_df = pd.concat(
        train_parts,
        ignore_index=True,
    )

    test_df = pd.concat(
        test_parts,
        ignore_index=True,
    )

    print("\n" + "=" * 90)
    print("BEFORE CLASS CAPPING")
    print("=" * 90)

    print("\nTraining distribution:")
    print(
        train_df[
            "Threat Class"
        ].value_counts().sort_index()
    )

    print("\nTest distribution:")
    print(
        test_df[
            "Threat Class"
        ].value_counts().sort_index()
    )

    train_df = cap_class_size(
        train_df,
        MAX_TRAIN_PER_CLASS,
    )

    test_df = cap_class_size(
        test_df,
        MAX_TEST_PER_CLASS,
    )

    print("\n" + "=" * 90)
    print("FINAL HOLDOUT EXPERIMENT DATA")
    print("=" * 90)

    print(
        f"Training rows: {len(train_df)}"
    )

    print(
        f"Test rows:     {len(test_df)}"
    )

    print("\nTraining distribution:")
    print(
        train_df[
            "Threat Class"
        ].value_counts().sort_index()
    )

    print("\nTest distribution:")
    print(
        test_df[
            "Threat Class"
        ].value_counts().sort_index()
    )

    # -------------------------------------------------------------
    # Prepare features
    # -------------------------------------------------------------

    X_train = train_df[
        FEATURES
    ]

    X_test = test_df[
        FEATURES
    ]

    y_train = train_df[
        "Threat Class"
    ]

    y_test = test_df[
        "Threat Class"
    ]

    label_encoder = LabelEncoder()

    y_train_encoded = (
        label_encoder.fit_transform(
            y_train
        )
    )

    y_test_encoded = (
        label_encoder.transform(
            y_test
        )
    )

    print("\nClasses:")
    for index, label in enumerate(
        label_encoder.classes_
    ):
        print(
            f"{index}: {label}"
        )

    # -------------------------------------------------------------
    # Train fresh model
    # -------------------------------------------------------------

    print("\n" + "=" * 90)
    print("TRAINING FRESH HOLDOUT MODEL")
    print("=" * 90)

    model = Pipeline(
        [
            (
                "imputer",
                SimpleImputer(
                    strategy="median"
                ),
            ),
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                    class_weight="balanced",
                ),
            ),
        ]
    )

    model.fit(
        X_train,
        y_train_encoded,
    )

    # -------------------------------------------------------------
    # Evaluate
    # -------------------------------------------------------------

    print("\nRunning held-out evaluation...")

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test_encoded,
        predictions,
    )

    precision, recall, f1, support = (
        precision_recall_fscore_support(
            y_test_encoded,
            predictions,
            labels=np.arange(
                len(label_encoder.classes_)
            ),
            zero_division=0,
        )
    )

    macro_f1 = float(
        np.mean(f1)
    )

    weighted_f1 = float(
        np.average(
            f1,
            weights=support,
        )
    )

    matrix = confusion_matrix(
        y_test_encoded,
        predictions,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
    )

    report = classification_report(
        y_test_encoded,
        predictions,
        labels=np.arange(
            len(label_encoder.classes_)
        ),
        target_names=label_encoder.classes_,
        digits=4,
        zero_division=0,
    )

    print("\n" + "=" * 90)
    print("HELD-OUT CICIDS EVALUATION")
    print("=" * 90)

    print(
        f"\nAccuracy:       {accuracy:.4f}"
    )

    print(
        f"Macro F1:       {macro_f1:.4f}"
    )

    print(
        f"Weighted F1:    {weighted_f1:.4f}"
    )

    print("\nClassification report:")
    print(report)

    print("Confusion matrix:")
    print(matrix)

    print("\nPer-class metrics:")

    for i, label in enumerate(
        label_encoder.classes_
    ):
        print(
            f"{label:15s} "
            f"precision={precision[i]:.4f} "
            f"recall={recall[i]:.4f} "
            f"f1={f1[i]:.4f} "
            f"support={support[i]}"
        )

    # -------------------------------------------------------------
    # Save separate validation model
    # -------------------------------------------------------------

    joblib.dump(
        model,
        MODEL_PATH,
        compress=3,
    )

    joblib.dump(
        label_encoder,
        ENCODER_PATH,
    )

    result = {
        "evaluation_type": (
            "per-source-file stratified holdout"
        ),
        "dataset": (
            "CICIDS2017 files available locally"
        ),
        "random_state": RANDOM_STATE,
        "test_size_per_source_file": TEST_SIZE,
        "max_train_per_class": MAX_TRAIN_PER_CLASS,
        "max_test_per_class": MAX_TEST_PER_CLASS,
        "limitations": [
            (
                "Raw files do not contain Flow ID, source IP, "
                "destination IP, protocol, or timestamp in the "
                "available copy."
            ),
            (
                "Therefore this is not a session-independent "
                "or temporal evaluation."
            ),
            (
                "Evaluation should be treated as a stronger "
                "holdout experiment than the previous random "
                "split, but not as a fully independent "
                "real-world benchmark."
            ),
        ],
        "source_summary": source_summary,
        "train_rows": int(len(train_df)),
        "test_rows": int(len(test_df)),
        "accuracy": float(accuracy),
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "classes": (
            label_encoder.classes_.tolist()
        ),
        "per_class": {
            str(label): {
                "precision": float(
                    precision[i]
                ),
                "recall": float(
                    recall[i]
                ),
                "f1": float(
                    f1[i]
                ),
                "support": int(
                    support[i]
                ),
            }
            for i, label in enumerate(
                label_encoder.classes_
            )
        },
        "confusion_matrix": matrix.tolist(),
        "model_path": str(
            MODEL_PATH
        ),
        "encoder_path": str(
            ENCODER_PATH
        ),
    }

    RESULT_PATH.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n" + "=" * 90)
    print("VALIDATION COMPLETE")
    print("=" * 90)

    print(
        "\nValidation model saved to:"
    )
    print(MODEL_PATH)

    print(
        "\nEvaluation results saved to:"
    )
    print(RESULT_PATH)


if __name__ == "__main__":
    main()
