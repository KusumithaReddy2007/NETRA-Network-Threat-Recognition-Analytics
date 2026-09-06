from pathlib import Path

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = BASE_DIR / "models" / "netra_cicids_model.joblib"
ENCODER_PATH = BASE_DIR / "models" / "netra_label_encoder.joblib"


model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(ENCODER_PATH)


FEATURE_COLUMNS = [
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
    "Idle Mean"
]


def predict_threat(flow_data: dict):

    input_data = pd.DataFrame(
        [flow_data],
        columns=FEATURE_COLUMNS
    )

    prediction_encoded = model.predict(input_data)[0]

    prediction = label_encoder.inverse_transform(
        [prediction_encoded]
    )[0]

    probabilities = model.predict_proba(input_data)[0]

    confidence = float(
        round(max(probabilities) * 100, 2)
    )

    return {
        "threat_class": prediction,
        "confidence": confidence
    }
