from pathlib import Path
import csv
import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

ROOT = Path("data/dns_exf_cicbell")

FEATURES = [
    "rr_name_entropy",
    "rr_name_length",
    "rr_count",
    "A_frequency",
    "NS_frequency",
    "CNAME_frequency",
    "SOA_frequency",
    "NULL_frequency",
    "PTR_frequency",
    "HINFO_frequency",
    "MX_frequency",
    "TXT_frequency",
    "AAAA_frequency",
    "SRV_frequency",
    "OPT_frequency",
    "ttl_mean",
    "ttl_variance",
]


def read_csv(path):
    rows = []

    with path.open(
        "r",
        newline="",
        encoding="utf-8",
        errors="replace",
    ) as f:
        reader = csv.DictReader(f)

        for row in reader:
            values = []

            for feature in FEATURES:
                try:
                    value = float(row.get(feature, 0) or 0)
                except (TypeError, ValueError):
                    value = 0.0

                if not np.isfinite(value):
                    value = 0.0

                values.append(value)

            rows.append(values)

    return rows


def load_files(paths):
    rows = []
    for path in paths:
        rows.extend(read_csv(path))
    return rows


def metrics(y_true, probabilities, threshold):
    y_pred = (probabilities >= threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn)

    return {
        "threshold": float(threshold),
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
    }


# ---------------------------------------------------------
# LIGHT TRAIN / HOLDOUT
# ---------------------------------------------------------
light_attack = sorted(
    (ROOT / "light_attack").rglob("*.csv")
)

attack_train_files = light_attack[:4]
attack_test_files = light_attack[4:]

X_attack_train = load_files(attack_train_files)
X_attack_test = load_files(attack_test_files)

light_benign_files = sorted(
    (ROOT / "light_benign").rglob("*.csv")
)

X_benign_all = load_files(light_benign_files)

cut = len(X_benign_all) // 2

X_benign_train = X_benign_all[:cut]
X_benign_test = X_benign_all[cut:]

X_train = np.asarray(
    X_attack_train + X_benign_train,
    dtype=np.float32,
)

y_train = np.asarray(
    [1] * len(X_attack_train)
    + [0] * len(X_benign_train),
    dtype=np.int8,
)

X_light_holdout = np.asarray(
    X_attack_test + X_benign_test,
    dtype=np.float32,
)

y_light_holdout = np.asarray(
    [1] * len(X_attack_test)
    + [0] * len(X_benign_test),
    dtype=np.int8,
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=26145,
    n_jobs=-1,
    class_weight="balanced",
    min_samples_leaf=2,
)

model.fit(X_train, y_train)

light_probability = model.predict_proba(X_light_holdout)[:, 1]

print("========== LIGHT THRESHOLD SWEEP ==========")

candidates = np.arange(0.05, 1.00, 0.05)

results = []

for threshold in candidates:
    result = metrics(
        y_light_holdout,
        light_probability,
        threshold,
    )
    results.append(result)

    print(
        f"threshold={threshold:.2f} "
        f"precision={result['precision']:.4f} "
        f"recall={result['recall']:.4f} "
        f"f1={result['f1']:.4f} "
        f"fpr={result['fpr']:.4f}"
    )


# Prefer thresholds with FPR <= 5%.
acceptable = [
    r for r in results
    if r["fpr"] <= 0.05 and r["recall"] >= 0.80
]

if acceptable:
    selected = max(
        acceptable,
        key=lambda r: (r["f1"], r["recall"]),
    )
else:
    # Fallback: minimum FPR while keeping the highest recall possible.
    selected = max(
        results,
        key=lambda r: (r["recall"] - 2.0 * r["fpr"]),
    )

threshold = selected["threshold"]

print("\n========== SELECTED THRESHOLD ==========")
print(json.dumps(selected, indent=2))


# ---------------------------------------------------------
# INDEPENDENT HEAVY TEST
# ---------------------------------------------------------
X_heavy_attack = np.asarray(
    load_files(sorted((ROOT / "heavy_attack").rglob("*.csv"))),
    dtype=np.float32,
)

X_heavy_benign = np.asarray(
    load_files(sorted((ROOT / "heavy_benign").rglob("*.csv"))),
    dtype=np.float32,
)

X_heavy = np.vstack([
    X_heavy_attack,
    X_heavy_benign,
])

y_heavy = np.asarray(
    [1] * len(X_heavy_attack)
    + [0] * len(X_heavy_benign),
    dtype=np.int8,
)

heavy_probability = model.predict_proba(X_heavy)[:, 1]

heavy_result = metrics(
    y_heavy,
    heavy_probability,
    threshold,
)

print("\n========== HEAVY INDEPENDENT TEST ==========")
print(json.dumps(heavy_result, indent=2))


output = {
    "dataset": "CIC-Bell DNS-EXF-2021",
    "method": "RandomForest with threshold selected on light holdout",
    "production_netra_dns_model_modified": False,
    "selected_threshold": threshold,
    "light_holdout_selected_metrics": selected,
    "heavy_independent_metrics": heavy_result,
}

out = Path("docs/SIH26145_CICBELL_DNS_EXF_THRESHOLD_VALIDATION.json")
out.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8",
)

print(f"\nSaved: {out}")
