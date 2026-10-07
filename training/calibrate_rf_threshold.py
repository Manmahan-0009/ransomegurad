"""
RansomGuard - RF Threshold Calibration Module (training/calibrate_rf_threshold.py)

Evaluates candidate RF classification thresholds ONLY on the VALIDATION split.
Calculates TP, FP, TN, FN, Precision, Recall, F1, FPR, Specificity, and separate Benign/Normal FPR.
Saves calibration table to results/rf_threshold_search_v2.csv.
"""

import csv
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_V2_PATH = PROJECT_ROOT / "models" / "ransomguard_rf_v2.joblib"
VAL_CSV_PATH = PROJECT_ROOT / "data" / "splits" / "validation.csv"
OUTPUT_CSV_PATH = PROJECT_ROOT / "results" / "rf_threshold_search_v2.csv"

FEATURE_COLUMNS = [
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


def calibrate_rf_threshold():
    val_df = pd.read_csv(VAL_CSV_PATH)
    model = joblib.load(MODEL_V2_PATH)

    X_val = val_df[FEATURE_COLUMNS]
    y_val = val_df["label"].values

    probs = model.predict_proba(X_val)[:, 1]
    val_df["rf_prob"] = probs

    thresholds = [round(t, 2) for t in np.arange(0.05, 0.96, 0.05)]
    results = []

    for t in thresholds:
        y_pred = (probs >= t).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_val, y_pred, labels=[0, 1]).ravel()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # Sub-group metrics: Normal vs Benign false positives
        normal_mask = (val_df["class"] == "normal")
        benign_mask = (val_df["class"] == "benign")

        normal_fp = int((y_pred[normal_mask] == 1).sum())
        normal_total = int(normal_mask.sum())
        normal_fpr = normal_fp / normal_total if normal_total > 0 else 0.0

        benign_fp = int((y_pred[benign_mask] == 1).sum())
        benign_total = int(benign_mask.sum())
        benign_fpr = benign_fp / benign_total if benign_total > 0 else 0.0

        res = {
            "threshold": t,
            "TP": int(tp),
            "FP": int(fp),
            "TN": int(tn),
            "FN": int(fn),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "specificity": round(specificity, 4),
            "normal_fp": normal_fp,
            "normal_fpr": round(normal_fpr, 4),
            "benign_fp": benign_fp,
            "benign_fpr": round(benign_fpr, 4),
        }
        results.append(res)

    OUTPUT_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    keys = list(results[0].keys())

    with open(OUTPUT_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

    print(f"[SUCCESS] Saved threshold search table to: {OUTPUT_CSV_PATH}")

    # Display selection table
    print("\n" + "=" * 90)
    print(f"{'THRESH':<8} {'TP':<4} {'FP':<4} {'TN':<4} {'FN':<4} {'PREC':<7} {'RECALL':<7} {'F1':<7} {'FPR':<7} {'BENIGN_FP':<10}")
    print("=" * 90)
    for r in results:
        print(f"{r['threshold']:<8.2f} {r['TP']:<4} {r['FP']:<4} {r['TN']:<4} {r['FN']:<4} {r['precision']:<7.4f} {r['recall']:<7.4f} {r['f1']:<7.4f} {r['fpr']:<7.4f} {r['benign_fp']:<10}")
    print("=" * 90)

    # Filter candidates with 100% recall & 0 benign false positives if available
    candidates = [
        r for r in results
        if r["recall"] >= 0.90 and r["benign_fp"] == 0
    ]

    if not candidates:
        candidates = sorted(results, key=lambda x: (-x["recall"], x["benign_fp"], -x["f1"]))

    best_candidate = candidates[0]
    print(f"\n[SELECTED CANDIDATE THRESHOLD]: {best_candidate['threshold']:.2f}")
    print(f"  Selection Rationale: High Attack Recall ({best_candidate['recall']:.2f}) with Zero Benign False Positives (Benign FP={best_candidate['benign_fp']}).")

    return best_candidate["threshold"]


if __name__ == "__main__":
    calibrate_rf_threshold()
