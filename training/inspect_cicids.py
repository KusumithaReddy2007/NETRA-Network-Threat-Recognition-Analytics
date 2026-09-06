import pandas as pd
from pathlib import Path

folder = Path("datasets/raw/MachineLearningCVE")

file = folder / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

df = pd.read_csv(file)

df.columns = df.columns.str.strip()

print("DATASET INFORMATION")
print("=" * 60)

print("\nShape:")
print(df.shape)

print("\nData types:")
print(df.dtypes)

print("\nMissing values:")
print(df.isnull().sum()[df.isnull().sum() > 0])

print("\nInfinite values:")

numeric_df = df.select_dtypes(include=["number"])

infinite_counts = (
    numeric_df
    .isin([float("inf"), float("-inf")])
    .sum()
)

print(infinite_counts[infinite_counts > 0])

print("\nColumn names:")
for i, column in enumerate(df.columns):
    print(f"{i}: {column}")
