"""
RansomGuard - Untouched Test Set Evaluation Module (training/evaluate_test_set.py)

Evaluates calibrated Model v2 + Rule Engine + Threat Score Engine + Debounce Engine
on the untouched TEST split (data/splits/test.csv).

Computes:
1. Window-Level Metrics (TP, TN, FP, FN, Precision, Recall, F1, FPR)
2. Run-Level Metrics (Per-run detection & false alert rates)

Saves report to results/test_evaluation_v2.json.
"""

import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

from backend.app.config import DetectionConfig
from backend.app.rule_engine import RuleEngine
from backend.app.threat_score import ThreatScoreEngine
from backend.app.debounce import DebounceEngine

MODEL_V2_PATH = PROJECT_ROOT / "models" / "ransomguard_rf_v2.joblib"
TEST_CSV_PATH = PROJECT_ROOT / "data" / "splits" / "test.csv"
OUTPUT_JSON_PATH = PROJECT_ROOT / "results" / "test_evaluation_v2.json"

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


def evaluate_test_set():
    test_df = pd.read_csv(TEST_CSV_PATH)
    model = joblib.load(MODEL_V2_PATH)

    # Calibrated V2 Configuration
    cfg = DetectionConfig(
        rf_threshold=0.20,
        ml_weight=0.70,
        rule_weight=0.30,
        critical_thresh=80.0,
        high_thresh=60.0,
        medium_thresh=30.0,
        consecutive_windows_required=2,
        immediate_critical_score=85.0,
    )

    rule_engine = RuleEngine(cfg=cfg)
    threat_score_engine = ThreatScoreEngine(cfg=cfg)

    X_test = test_df[FEATURE_COLUMNS]
    y_test = test_df["label"].values

    ml_probs = model.predict_proba(X_test)[:, 1]

    window_results = []
    for idx, row in test_df.iterrows():
        feat_dict = row[FEATURE_COLUMNS].to_dict()
        ml_prob = ml_probs[idx]
        rule_res = rule_engine.evaluate(feat_dict)
        score_res = threat_score_engine.calculate(ml_prob, rule_res["rule_score"])

        window_results.append({
            "run_id": row["run_id"],
            "class": row["class"],
            "label": int(row["label"]),
            "ml_prob": round(float(ml_prob), 4),
            "rule_score": rule_res["rule_score"],
            "threat_score": score_res["threat_score"],
            "raw_severity": score_res["severity"],
            "pred_label": 1 if score_res["threat_score"] >= cfg.medium_thresh else 0,
        })

    res_df = pd.DataFrame(window_results)

    # 1. WINDOW-LEVEL METRICS
    y_pred = res_df["pred_label"].values
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    window_metrics = {
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
    }

    # 2. RUN-LEVEL METRICS (Grouped evaluation)
    run_metrics_list = []
    run_groups = res_df.groupby(["run_id", "class"])

    for (run_id, run_cls), group_df in run_groups:
        debounce_engine = DebounceEngine(cfg=cfg)
        raw_severities = group_df["raw_severity"].tolist()
        threat_scores = group_df["threat_score"].tolist()

        run_detected = False
        run_debounced_alert = False

        for score, sev in zip(threat_scores, raw_severities):
            deb_res = debounce_engine.evaluate(score, sev)
            if sev in ["HIGH", "CRITICAL"]:
                run_detected = True
            if deb_res["debounced_alert"]:
                run_debounced_alert = True

        run_metrics_list.append({
            "run_id": run_id,
            "class": run_cls,
            "total_windows": len(group_df),
            "attack_positive_windows": int((group_df["label"] == 1).sum()),
            "max_threat_score": float(group_df["threat_score"].max()),
            "raw_threat_detected": run_detected,
            "debounced_alert_triggered": run_debounced_alert,
        })

    run_summary_df = pd.DataFrame(run_metrics_list)

    normal_runs = run_summary_df[run_summary_df["class"] == "normal"]
    benign_runs = run_summary_df[run_summary_df["class"] == "benign"]
    attack_runs = run_summary_df[run_summary_df["class"] == "attack"]

    normal_fa_count = int(normal_runs["debounced_alert_triggered"].sum())
    benign_fa_count = int(benign_runs["debounced_alert_triggered"].sum())
    attack_det_count = int(attack_runs["debounced_alert_triggered"].sum())

    run_level_metrics = {
        "normal_runs_total": len(normal_runs),
        "normal_false_alerts": normal_fa_count,
        "normal_false_alert_rate": round(normal_fa_count / len(normal_runs), 4) if len(normal_runs) > 0 else 0.0,
        "benign_runs_total": len(benign_runs),
        "benign_false_alerts": benign_fa_count,
        "benign_false_alert_rate": round(benign_fa_count / len(benign_runs), 4) if len(benign_runs) > 0 else 0.0,
        "attack_runs_total": len(attack_runs),
        "attack_runs_detected": attack_det_count,
        "attack_run_recall": round(attack_det_count / len(attack_runs), 4) if len(attack_runs) > 0 else 0.0,
    }

    final_report = {
        "config": {
            "model_version": cfg.model_version,
            "feature_schema_version": cfg.feature_schema_version,
            "rf_threshold": cfg.rf_threshold,
            "ml_weight": cfg.ml_weight,
            "rule_weight": cfg.rule_weight,
            "critical_thresh": cfg.critical_thresh,
            "high_thresh": cfg.high_thresh,
            "medium_thresh": cfg.medium_thresh,
            "consecutive_windows_required": cfg.consecutive_windows_required,
        },
        "window_level_metrics": window_metrics,
        "run_level_metrics": run_level_metrics,
        "per_run_breakdown": run_metrics_list,
    }

    OUTPUT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    print("=" * 60)
    print("      UNTOUCHED TEST SET FINAL EVALUATION RESULTS      ")
    print("=" * 60)
    print("WINDOW-LEVEL METRICS:")
    print(f"  Precision : {window_metrics['precision']:.4f}")
    print(f"  Recall    : {window_metrics['recall']:.4f}")
    print(f"  F1 Score  : {window_metrics['f1']:.4f}")
    print(f"  FPR       : {window_metrics['fpr']:.4f}")
    print("\nRUN-LEVEL METRICS:")
    print(f"  Attack Run Recall             : {run_level_metrics['attack_run_recall']:.4f} ({attack_det_count}/{len(attack_runs)})")
    print(f"  Benign False-Positive Rate    : {run_level_metrics['benign_false_alert_rate']:.4f} ({benign_fa_count}/{len(benign_runs)})")
    print(f"  Normal False-Positive Rate    : {run_level_metrics['normal_false_alert_rate']:.4f} ({normal_fa_count}/{len(normal_runs)})")
    print("=" * 60)
    print(f"[SUCCESS] Test evaluation saved to: {OUTPUT_JSON_PATH}")

    return final_report


if __name__ == "__main__":
    evaluate_test_set()
