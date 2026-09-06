import pandas as pd
import json


DATASET_PATH = "datasets/processed/netra_cicids_balanced_v1.csv"

df = pd.read_csv(DATASET_PATH)


# Classes we want to test
test_classes = [
    "BENIGN",
    "DDOS",
    "PORTSCAN",
    "DOS"
]


for threat_class in test_classes:

    print("\n" + "=" * 70)
    print(f"REAL CIC-IDS2017 FLOW: {threat_class}")
    print("=" * 70)

    row = df[
        df["Threat Class"] == threat_class
    ].sample(
        n=1,
        random_state=42
    )

    row = row.drop(
        columns=["Threat Class"]
    )

    flow = row.iloc[0].to_dict()

    print(
        json.dumps(
            flow,
            indent=2,
            default=float
        )
    )
