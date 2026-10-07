"""
RansomGuard - Dataset Analysis Module (training/analyze_dataset.py)

Summarizes numerical feature distributions across normal, benign, attack-positive,
and attack-negative windows. Saves analysis report to results/dataset_analysis_v2.json.
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_CSV = PROJECT_ROOT / "data" / "datasets" / "dataset_v1.csv"
OUTPUT_JSON = PROJECT_ROOT / "results" / "dataset_analysis_v2.json"

FEATURE_COLS = [
    "files_created",
    "files_modified",
    "files_deleted",
    "files_renamed",
    "writes_per_second",
    "unique_extensions",
    "unique_directories",
    "extension_change_count",
    "rename_ratio",
    "mean_entropy",
    "entropy_change",
]


def summarize_series(series: pd.Series) -> dict:
    if series.empty:
        return {
            "count": 0, "min": 0.0, "max": 0.0, "mean": 0.0,
            "median": 0.0, "std": 0.0, "p50": 0.0, "p75": 0.0,
            "p90": 0.0, "p95": 0.0,
        }
    arr = series.to_numpy()
    return {
        "count": int(len(arr)),
        "min": round(float(np.min(arr)), 4),
        "max": round(float(np.max(arr)), 4),
        "mean": round(float(np.mean(arr)), 4),
        "median": round(float(np.median(arr)), 4),
        "std": round(float(np.std(arr)), 4),
        "p50": round(float(np.percentile(arr, 50)), 4),
        "p75": round(float(np.percentile(arr, 75)), 4),
        "p90": round(float(np.percentile(arr, 90)), 4),
        "p95": round(float(np.percentile(arr, 95)), 4),
    }


def analyze_dataset() -> dict:
    df = pd.read_csv(DATASET_CSV)

    normal_df = df[df["class"] == "normal"]
    benign_df = df[df["class"] == "benign"]
    attack_pos_df = df[(df["class"] == "attack") & (df["label"] == 1)]
    attack_neg_df = df[(df["class"] == "attack") & (df["label"] == 0)]

    analysis = {
        "dataset_summary": {
            "total_rows": int(len(df)),
            "total_runs": int(df["run_id"].nunique()),
            "class_counts": {
                "normal": int(len(normal_df)),
                "benign": int(len(benign_df)),
                "attack": int(len(df[df["class"] == "attack"])),
            },
            "label_counts": {
                "positive_1": int((df["label"] == 1).sum()),
                "negative_0": int((df["label"] == 0).sum()),
            },
        },
        "feature_distributions": {},
    }

    groups = {
        "normal": normal_df,
        "benign": benign_df,
        "attack_positive": attack_pos_df,
        "attack_negative": attack_neg_df,
    }

    for feature in FEATURE_COLS:
        analysis["feature_distributions"][feature] = {}
        for group_name, group_df in groups.items():
            analysis["feature_distributions"][feature][group_name] = summarize_series(group_df[feature])

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    print(f"[SUCCESS] Dataset analysis complete. Saved to: {OUTPUT_JSON}")
    return analysis


if __name__ == "__main__":
    analyze_dataset()
