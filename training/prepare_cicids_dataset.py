from pathlib import Path
import pandas as pd
import numpy as np


RAW_DATA_DIR = Path("datasets/raw/MachineLearningCVE")
OUTPUT_FILE = Path("datasets/processed/netra_cicids_v1.csv")


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


def map_label(label):

    label = str(label).strip()

    if label == "BENIGN":
        return "BENIGN"

    if label == "DDoS":
        return "DDOS"

    if label == "PortScan":
        return "PORTSCAN"

    if label == "Bot":
        return "BOT"

    if label in ["FTP-Patator", "SSH-Patator"]:
        return "BRUTE_FORCE"

    if label in [
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
    ]:
        return "DOS"

    if "Web Attack" in label:
        return "WEB_ATTACK"

    return None


all_data = []


print("Starting CIC-IDS2017 dataset preparation...")
print("=" * 70)


for file in sorted(RAW_DATA_DIR.glob("*.csv")):

    print(f"\nProcessing: {file.name}")

    df = pd.read_csv(file)

    # Remove spaces from column names
    df.columns = df.columns.str.strip()

    # Replace infinity with NaN
    df = df.replace([np.inf, -np.inf], np.nan)

    # Keep only required features + Label
    required_columns = FEATURES + ["Label"]

    df = df[required_columns]

    # Remove rows containing missing values
    before_rows = len(df)

    df = df.dropna()

    removed_rows = before_rows - len(df)

    print(f"Rows after cleaning: {len(df)}")
    print(f"Rows removed: {removed_rows}")

    # Map attack labels to NETRA categories
    df["Threat Class"] = df["Label"].apply(map_label)

    # Remove unsupported/rare labels
    df = df.dropna(subset=["Threat Class"])

    # Remove original label
    df = df.drop(columns=["Label"])

    print("\nNETRA labels:")
    print(df["Threat Class"].value_counts())

    all_data.append(df)


print("\nCombining all files...")

combined_df = pd.concat(all_data, ignore_index=True)


print("\n" + "=" * 70)
print("COMBINED DATASET")

print("\nShape:")
print(combined_df.shape)

print("\nThreat class distribution:")
print(combined_df["Threat Class"].value_counts())


OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

combined_df.to_csv(OUTPUT_FILE, index=False)


print("\n" + "=" * 70)
print("SUCCESS")

print(f"Processed dataset saved to:")
print(OUTPUT_FILE.resolve())

print(f"\nFinal dataset shape: {combined_df.shape}")
