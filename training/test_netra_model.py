from pathlib import Path
import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[1]

MODEL_PATH = BASE_DIR / "models" / "netra_cicids_model.joblib"
ENCODER_PATH = BASE_DIR / "models" / "netra_label_encoder.joblib"


print("Loading model...")

model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)

print("Model loaded successfully.")
print()


sample_data = pd.DataFrame([
    {
        "Destination Port": 80,
        "Flow Duration": 1000000,
        "Total Fwd Packets": 100,
        "Total Backward Packets": 80,
        "Total Length of Fwd Packets": 50000,
        "Total Length of Bwd Packets": 40000,
        "Flow Bytes/s": 90000,
        "Flow Packets/s": 180,
        "Flow IAT Mean": 5000,
        "Flow IAT Std": 1000,
        "Fwd Packet Length Mean": 500,
        "Bwd Packet Length Mean": 500,
        "Packet Length Mean": 500,
        "Packet Length Std": 50,
        "SYN Flag Count": 1,
        "ACK Flag Count": 150,
        "Down/Up Ratio": 1,
        "Average Packet Size": 500,
        "Active Mean": 500000,
        "Idle Mean": 100000
    }
])


print("Running prediction...")

prediction_encoded = model.predict(sample_data)[0]

prediction = label_encoder.inverse_transform(
    [prediction_encoded]
)[0]

probabilities = model.predict_proba(sample_data)[0]

confidence = float(round(max(probabilities) * 100, 2))


print()
print("=" * 50)
print("NETRA PREDICTION RESULT")
print("=" * 50)

print("Threat Class:", prediction)
print("Confidence:", confidence, "%")
