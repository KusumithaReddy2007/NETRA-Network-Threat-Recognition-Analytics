from pathlib import Path
import csv
import json

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

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


def load_dirs(directories):
    rows = []

    for directory in directories:
        for path in sorted(directory.rglob("*.csv")):
            rows.extend(read_csv(path))

    return rows


def metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    return {
        "rows": int(len(y_true)),
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "recall": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "f1": float(
            f1_score(y_true, y_pred, zero_division=0)
        ),
        "false_positive_rate": float(
            fp / (fp + tn) if fp + tn else 0.0
        ),
    }


# --------------------------------------------------
# LIGHT CALIBRATION
# --------------------------------------------------
light_attack_files = sorted(
    (ROOT / "light_attack").rglob("*.csv")
)

light_attack_train_files = light_attack_files[:4]
light_attack_test_files = light_attack_files[4:]

X_attack_train = load_dirs(
    [p.parent for p in light_attack_train_files]
)

# Reload exactly the selected four files so their
# parent directories don't pull in other files.
X_attack_train = []
for path in light_attack_train_files:
    X_attack_train.extend(read_csv(path))

X_attack_test = []
for path in light_attack_test_files:
    X_attack_test.extend(read_csv(path))


# Light benign has one stateful file.
light_benign_files = sorted(
    (ROOT / "light_benign").rglob("*.csv")
)

X_benign_all = []
for path in light_benign_files:
    X_benign_all.extend(read_csv(path))

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

X_light_test = np.asarray(
    X_attack_test + X_benign_test,
    dtype=np.float32,
)

y_light_test = np.asarray(
    [1] * len(X_attack_test)
    + [0] * len(X_benign_test),
    dtype=np.int8,
)


print("========== TRAINING DATA ==========")
print("attack:", len(X_attack_train))
print("benign:", len(X_benign_train))
print("total:", len(X_train))

print("\n========== LIGHT HELD-OUT ==========")
print(
    metrics(
        y_light_test,
        RandomForestClassifier(
            n_estimators=300,
            random_state=26145,
            n_jobs=-1,
            class_weight="balanced",
            min_samples_leaf=2,
        ).fit(X_train, y_train).predict(X_light_test),
    )
)


# --------------------------------------------------
# Train final validation model on all light data
# and test on completely independent heavy data.
# --------------------------------------------------
X_light_all = np.asarray(
    X_attack_train + X_attack_test + X_benign_all,
    dtype=np.float32,
)

y_light_all = np.asarray(
    [1] * (len(X_attack_train) + len(X_attack_test))
    + [0] * len(X_benign_all),
    dtype=np.int8,
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=26145,
    n_jobs=-1,
    class_weight="balanced",
    min_samples_leaf=2,
)

model.fit(X_light_all, y_light_all)


X_heavy_attack = np.asarray(
    load_dirs([ROOT / "heavy_attack"]),
    dtype=np.float32,
)

X_heavy_benign = np.asarray(
    load_dirs([ROOT / "heavy_benign"]),
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

print("\n========== HEAVY INDEPENDENT ==========")
print(
    metrics(
        y_heavy,
        model.predict(X_heavy),
    )
)

print("\n========== FEATURE IMPORTANCE ==========")

importance = sorted(
    zip(FEATURES, model.feature_importances_),
    key=lambda x: x[1],
    reverse=True,
)

for feature, value in importance:
    print(f"{feature:20s} {value:.6f}")


result = {
    "dataset": "CIC-Bell DNS-EXF-2021",
    "method": "Dedicated RandomForest binary validation classifier",
    "production_netra_dns_model_modified": False,
    "features": FEATURES,
    "light_held_out": metrics(
        y_light_test,
        RandomForestClassifier(
            n_estimators=300,
            random_state=26145,
            n_jobs=-1,
            class_weight="balanced",
            min_samples_leaf=2,
        ).fit(X_train, y_train).predict(X_light_test),
    ),
    "heavy_independent": metrics(
        y_heavy,
        model.predict(X_heavy),
    ),
    "feature_importance": [
        {"feature": f, "importance": float(v)}
        for f, v in importance
    ],
}

out = Path("docs/SIH26145_CICBELL_DNS_EXF_ML_VALIDATION.json")
out.write_text(
    json.dumps(result, indent=2),
    encoding="utf-8",
)

print(f"\nSaved: {out}")
