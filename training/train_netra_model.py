import pandas as pd
import joblib

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "netra_cicids_balanced_v1.csv"
)

MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "netra_cicids_model.joblib"

ENCODER_PATH = MODEL_DIR / "netra_label_encoder.joblib"


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading balanced NETRA dataset...")

df = pd.read_csv(DATASET_PATH)

print("\nDataset shape:")
print(df.shape)

print("\nThreat class distribution:")
print(df["Threat Class"].value_counts())


# ============================================================
# PREPARE FEATURES
# ============================================================

print("\nPreparing features...")

X = df.drop(columns=["Threat Class"])

y = df["Threat Class"]


# ============================================================
# ENCODE LABELS
# ============================================================

label_encoder = LabelEncoder()

y_encoded = label_encoder.fit_transform(y)

print("\nThreat classes:")

for index, label in enumerate(label_encoder.classes_):
    print(f"{index}: {label}")


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y_encoded,
    test_size=0.2,
    random_state=42,
    stratify=y_encoded
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================================
# MACHINE LEARNING PIPELINE
# ============================================================

print("\nCreating ML pipeline...")

model = Pipeline([
    (
        "imputer",
        SimpleImputer(strategy="median")
    ),
    (
        "scaler",
        StandardScaler()
    ),
    (
        "classifier",
        RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        )
    )
])


# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining NETRA machine learning model...")

model.fit(X_train, y_train)

print("\nTraining completed successfully.")


# ============================================================
# EVALUATE MODEL
# ============================================================

print("\nRunning evaluation...")

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nModel Accuracy:")
print(round(accuracy * 100, 2), "%")


print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=label_encoder.classes_
    )
)


# ============================================================
# SAVE MODEL
# ============================================================

MODEL_DIR.mkdir(
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)

joblib.dump(
    label_encoder,
    ENCODER_PATH
)


print("\n" + "=" * 60)

print("SUCCESS")

print("\nModel saved to:")
print(MODEL_PATH)

print("\nLabel encoder saved to:")
print(ENCODER_PATH)

print("=" * 60)
