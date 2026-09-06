from pathlib import Path
import csv
import math
import json
from collections import Counter

ROOT = Path("data/dns_exf_cicbell")

ATTACK_DIRS = [
    ROOT / "light_attack",
    ROOT / "heavy_attack",
]

BENIGN_DIRS = [
    ROOT / "light_benign",
    ROOT / "heavy_benign",
]


def to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def entropy_from_rr_types(value):
    """
    Convert dataset rr_type representation such as
    "{'A'}", "{'A', 'AAAA'}", "{None}", "set()"
    into a simple diversity entropy.
    """
    if not value:
        return 0.0

    value = value.strip()

    if value in {"set()", "{None}", "None"}:
        return 0.0

    inner = value.strip("{}").strip()
    if not inner:
        return 0.0

    parts = [p.strip().strip("'\"") for p in inner.split(",")]
    parts = [p for p in parts if p and p.lower() != "none"]

    if not parts:
        return 0.0

    counts = Counter(parts)
    total = sum(counts.values())

    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)

    return result


def detect_exfiltration(row):
    """
    Independent CIC-Bell validation heuristic.

    This is deliberately separate from NETRA's production DNS ML model.
    It uses only fields available in the CIC-Bell stateful CSVs.
    """
    entropy = to_float(row.get("rr_name_entropy"))
    name_length = to_float(row.get("rr_name_length"))
    distinct_domains = to_float(row.get("distinct_domains"))
    rr_count = to_float(row.get("rr_count"))
    txt = to_float(row.get("TXT_frequency"))
    null = to_float(row.get("NULL_frequency"))
    ttl_variance = to_float(row.get("ttl_variance"))
    rr_type_entropy = entropy_from_rr_types(row.get("rr_type"))

    signals = []
    score = 0.0

    # DNS-label complexity
    if entropy >= 3.0:
        signals.append("high_dns_name_entropy")
        score += 25.0

    if name_length >= 24:
        signals.append("long_dns_name")
        score += 20.0

    # Response / record anomalies
    if txt > 0:
        signals.append("txt_activity")
        score += 15.0

    if null > 0:
        signals.append("null_activity")
        score += 15.0

    if distinct_domains >= 5:
        signals.append("high_domain_diversity")
        score += 10.0

    if rr_count >= 5:
        signals.append("high_rr_count")
        score += 5.0

    if ttl_variance > 0:
        signals.append("ttl_variance")
        score += 5.0

    if rr_type_entropy > 0:
        signals.append("rr_type_diversity")
        score += 5.0

    return score >= 50.0, min(score, 100.0), signals


def process_file(path, expected_label):
    rows = 0
    predicted_attack = 0
    tp = fp = tn = fn = 0

    with path.open("r", newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)

        for row in reader:
            rows += 1

            predicted, score, signals = detect_exfiltration(row)

            if expected_label == "DNS_EXFILTRATION":
                if predicted:
                    tp += 1
                    predicted_attack += 1
                else:
                    fn += 1
            else:
                if predicted:
                    fp += 1
                    predicted_attack += 1
                else:
                    tn += 1

    return {
        "file": str(path),
        "label": expected_label,
        "rows": rows,
        "predicted_attack": predicted_attack,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def summarize(results):
    tp = sum(r["tp"] for r in results)
    fp = sum(r["fp"] for r in results)
    tn = sum(r["tn"] for r in results)
    fn = sum(r["fn"] for r in results)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0

    return {
        "rows": tp + fp + tn + fn,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": fpr,
    }


def run_subset(name, attack_dirs, benign_dirs):
    results = []

    for directory in attack_dirs:
        for path in sorted(directory.rglob("*.csv")):
            results.append(process_file(path, "DNS_EXFILTRATION"))

    for directory in benign_dirs:
        for path in sorted(directory.rglob("*.csv")):
            results.append(process_file(path, "BENIGN"))

    return {
        "dataset": "CIC-Bell DNS-EXF-2021",
        "subset": name,
        "files": results,
        "summary": summarize(results),
    }


def main():
    light = run_subset(
        "LIGHT_STATEFUL",
        [ROOT / "light_attack"],
        [ROOT / "light_benign"],
    )

    heavy = run_subset(
        "HEAVY_STATEFUL",
        [ROOT / "heavy_attack"],
        [ROOT / "heavy_benign"],
    )

    combined = run_subset(
        "ALL_STATEFUL",
        ATTACK_DIRS,
        BENIGN_DIRS,
    )

    output = {
        "dataset": "CIC-Bell DNS-EXF-2021",
        "method": "Independent rule-based DNS exfiltration validation",
        "production_model_unchanged": True,
        "subsets": {
            "light": light,
            "heavy": heavy,
            "combined": combined,
        },
    }

    out_path = Path("docs/SIH26145_CICBELL_DNS_EXF_VALIDATION.json")
    out_path.write_text(json.dumps(output, indent=2), encoding="utf-8")

    for subset_name, subset in output["subsets"].items():
        print(f"\n========== {subset_name.upper()} ==========")
        print(json.dumps(subset["summary"], indent=2))

    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
