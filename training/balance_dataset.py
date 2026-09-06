from pathlib import Path
import pandas as pd


INPUT_FILE = Path("datasets/processed/netra_cicids_v1.csv")

OUTPUT_FILE = Path(
    "datasets/processed/netra_cicids_balanced_v1.csv"
)


SAMPLES_PER_CLASS = {
    "BENIGN": 50000,
    "DOS": 50000,
    "PORTSCAN": 50000,
    "DDOS": 50000,
    "BRUTE_FORCE": 50000,
    "WEB_ATTACK": 50000,
    "BOT": 50000,
}


RANDOM_STATE = 42


print("Loading processed NETRA dataset...")

df = pd.read_csv(INPUT_FILE)

print("\nOriginal dataset shape:")
print(df.shape)

print("\nOriginal class distribution:")
print(df["Threat Class"].value_counts())


balanced_data = []


print("\nBalancing classes...")
print("=" * 60)


for threat_class, max_samples in SAMPLES_PER_CLASS.items():

    class_df = df[
        df["Threat Class"] == threat_class
    ]

    available_samples = len(class_df)

    samples_to_take = min(
        available_samples,
        max_samples
    )

    sampled_df = class_df.sample(
        n=samples_to_take,
        random_state=RANDOM_STATE
    )

    balanced_data.append(sampled_df)

    print(
        f"{threat_class}: "
        f"{samples_to_take} samples selected "
        f"(available: {available_samples})"
    )


balanced_df = pd.concat(
    balanced_data,
    ignore_index=True
)


balanced_df = balanced_df.sample(
    frac=1,
    random_state=RANDOM_STATE
).reset_index(drop=True)


print("\n" + "=" * 60)
print("BALANCED DATASET")

print("\nShape:")
print(balanced_df.shape)

print("\nClass distribution:")
print(
    balanced_df["Threat Class"]
    .value_counts()
)


OUTPUT_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)


balanced_df.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n" + "=" * 60)
print("SUCCESS")

print("\nBalanced dataset saved to:")
print(OUTPUT_FILE.resolve())
