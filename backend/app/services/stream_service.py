import time
from pathlib import Path

import pandas as pd

from app.services.ml_service import predict_threat
from app.services.alert_service import create_alert


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


BASE_DIR = Path(__file__).resolve().parents[3]

DATASET_PATH = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "netra_cicids_balanced_v1.csv"
)


def stream_flows(
    max_flows: int = 100,
    delay: float = 0.0
):

    print("Loading dataset for streaming...")

    dataframe = pd.read_csv(
        DATASET_PATH,
        nrows=max_flows
    )

    total_flows = len(dataframe)

    print(f"Streaming {total_flows} flows...")
    print("=" * 70)

    start_time = time.perf_counter()

    results = []
    alerts = []

    for index, row in dataframe.iterrows():

        flow_data = {
            feature: row[feature]
            for feature in FEATURE_COLUMNS
        }

        expected_class = row["Threat Class"]

        flow_start = time.perf_counter()

        ml_analysis = predict_threat(flow_data)

        predicted_class = ml_analysis["threat_class"]

        alert = None

        if predicted_class != "BENIGN":
            alert = create_alert(
                flow_data,
                ml_analysis
            )

            alerts.append(alert)

        processing_time_ms = (
            time.perf_counter() - flow_start
        ) * 1000

        result = {
            "flow_number": index + 1,
            "expected_class": expected_class,
            "predicted_class": predicted_class,
            "confidence": ml_analysis["confidence"],
            "alert_generated": alert is not None,
            "severity": (
                alert["severity"]
                if alert else None
            ),
            "processing_time_ms": round(
                processing_time_ms,
                3
            )
        }

        results.append(result)

        if delay > 0:
            time.sleep(delay)

    total_time = (
        time.perf_counter() - start_time
    )

    flows_per_second = (
        total_flows / total_time
        if total_time > 0
        else 0
    )

    return {
        "total_flows": total_flows,
        "total_alerts": len(alerts),
        "total_time_seconds": round(
            total_time,
            3
        ),
        "flows_per_second": round(
            flows_per_second,
            2
        ),
        "results": results,
        "alerts": alerts
    }
