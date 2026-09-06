import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "backend"))

from app.services.ml_service import predict_threat


real_flows = {

    "BENIGN": {
        "Destination Port": 80.0,
        "Flow Duration": 5428673.0,
        "Total Fwd Packets": 3.0,
        "Total Backward Packets": 1.0,
        "Total Length of Fwd Packets": 12.0,
        "Total Length of Bwd Packets": 0.0,
        "Flow Bytes/s": 2.210484956,
        "Flow Packets/s": 0.736828319,
        "Flow IAT Mean": 1809557.667,
        "Flow IAT Std": 2939501.602,
        "Fwd Packet Length Mean": 4.0,
        "Bwd Packet Length Mean": 0.0,
        "Packet Length Mean": 2.4,
        "Packet Length Std": 3.286335345,
        "SYN Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 3.0,
        "Active Mean": 0.0,
        "Idle Mean": 0.0
    },

    "DDOS": {
        "Destination Port": 80.0,
        "Flow Duration": 99867723.0,
        "Total Fwd Packets": 8.0,
        "Total Backward Packets": 5.0,
        "Total Length of Fwd Packets": 56.0,
        "Total Length of Bwd Packets": 11607.0,
        "Flow Bytes/s": 116.784479,
        "Flow Packets/s": 0.130172188,
        "Flow IAT Mean": 8322310.25,
        "Flow IAT Std": 24900000.0,
        "Fwd Packet Length Mean": 7.0,
        "Bwd Packet Length Mean": 2321.4,
        "Packet Length Mean": 833.5,
        "Packet Length Std": 2705.044255,
        "SYN Flag Count": 0.0,
        "ACK Flag Count": 1.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 897.6153846,
        "Active Mean": 2015.0,
        "Idle Mean": 49500000.0
    },

    "PORTSCAN": {
        "Destination Port": 5440.0,
        "Flow Duration": 11.0,
        "Total Fwd Packets": 1.0,
        "Total Backward Packets": 1.0,
        "Total Length of Fwd Packets": 2.0,
        "Total Length of Bwd Packets": 6.0,
        "Flow Bytes/s": 727272.7273,
        "Flow Packets/s": 181818.1818,
        "Flow IAT Mean": 11.0,
        "Flow IAT Std": 0.0,
        "Fwd Packet Length Mean": 2.0,
        "Bwd Packet Length Mean": 6.0,
        "Packet Length Mean": 3.333333333,
        "Packet Length Std": 2.309401077,
        "SYN Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "Down/Up Ratio": 1.0,
        "Average Packet Size": 5.0,
        "Active Mean": 0.0,
        "Idle Mean": 0.0
    },

    "DOS": {
        "Destination Port": 80.0,
        "Flow Duration": 1989.0,
        "Total Fwd Packets": 4.0,
        "Total Backward Packets": 0.0,
        "Total Length of Fwd Packets": 6.0,
        "Total Length of Bwd Packets": 0.0,
        "Flow Bytes/s": 3016.591252,
        "Flow Packets/s": 2011.060835,
        "Flow IAT Mean": 663.0,
        "Flow IAT Std": 1105.309007,
        "Fwd Packet Length Mean": 1.5,
        "Bwd Packet Length Mean": 0.0,
        "Packet Length Mean": 1.2,
        "Packet Length Std": 2.683281573,
        "SYN Flag Count": 0.0,
        "ACK Flag Count": 1.0,
        "Down/Up Ratio": 0.0,
        "Average Packet Size": 1.5,
        "Active Mean": 0.0,
        "Idle Mean": 0.0
    }
}


print("\nNETRA REAL CIC-IDS2017 FLOW TEST")
print("=" * 70)

for expected_class, flow in real_flows.items():

    result = predict_threat(flow)

    predicted_class = result["threat_class"]
    confidence = result["confidence"]

    print(f"\nExpected:   {expected_class}")
    print(f"Predicted:  {predicted_class}")
    print(f"Confidence: {confidence}%")

    if expected_class == predicted_class:
        print("Result:     CORRECT")
    else:
        print("Result:     INCORRECT")

print("\n" + "=" * 70)
