import pandas as pd
import joblib

from pathlib import Path
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier


# Project root
BASE_DIR = Path(__file__).resolve().parent.parent

# Dataset path
DATASET_PATH = BASE_DIR / "datasets" / "network_traffic.csv"

# Model path
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "netra_model.joblib"


# Load dataset
data = pd.read_csv(DATASET_PATH)

print("Dataset loaded successfully")
print(data.head())


# Features and target
X = data[["protocol", "packet_size"]]
y = data["label"]


# Preprocess categorical protocol column
preprocessor = ColumnTransformer(
    transformers=[
        (
            "protocol",
            OneHotEncoder(handle_unknown="ignore"),
            ["protocol"]
        )
    ],
    remainder="passthrough"
)


# Create ML pipeline
model = Pipeline(
    steps=[
        ("preprocessor", preprocessor),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                random_state=42
            )
        )
    ]
)


# Train model
model.fit(X, y)

print("\nModel training completed successfully")


# Create models directory if needed
MODEL_DIR.mkdir(exist_ok=True)


# Save trained model
joblib.dump(model, MODEL_PATH)

print(f"Model saved successfully at: {MODEL_PATH}")
