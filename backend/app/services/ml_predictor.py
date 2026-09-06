from pathlib import Path
import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = BASE_DIR / "models" / "netra_model.joblib"


model = joblib.load(MODEL_PATH)


def predict_threat(protocol: str, packet_size: int):

    input_data = pd.DataFrame(
        [{
            "protocol": protocol,
            "packet_size": packet_size
        }]
    )

    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]

    confidence = float(max(probabilities))

    return {
        "prediction": prediction,
        "confidence": round(confidence * 100, 2)
    }
