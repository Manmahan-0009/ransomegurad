"""
RansomGuard - Rule Calibration Module (training/calibrate_rules.py)

Evaluates rule triggers across TRAIN and VALIDATION splits.
Saves calibration findings to results/rule_calibration_v2.json.
"""

import json
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRAIN_CSV = PROJECT_ROOT / "data" / "splits" / "train.csv"
VAL_CSV = PROJECT_ROOT / "data" / "splits" / "validation.csv"
OUTPUT_JSON = PROJECT_ROOT / "results" / "rule_calibration_v2.json"


def evaluate_rules_on_df(df: pd.DataFrame, cfg: dict) -> dict:
    normal_df = df[df["class"] == "normal"]
    benign_df = df[df["class"] == "benign"]
    attack_pos_df = df[(df["class"] == "attack") & (df["label"] == 1)]

    def rule_counts(sub_df):
        total = len(sub_df)
        if total == 0:
            return {}

        w_rate = (sub_df["writes_per_second"] >= cfg["writes_per_sec_thresh"]).sum()
        mass_mod = (sub_df["files_modified"] >= cfg["files_modified_thresh"]).sum()
        h_ent = (sub_df["mean_entropy"] >= cfg["mean_entropy_thresh"]).sum()
        ent_inc = (sub_df["entropy_change"] >= cfg["entropy_change_thresh"]).sum()
        ext_chg = (sub_df["extension_change_count"] >= cfg["ext_change_count_thresh"]).sum()
        high_ren = (
            (sub_df["rename_ratio"] >= cfg["rename_ratio_thresh"]) &
            (sub_df["files_renamed"] >= cfg["min_rename_count"])
        ).sum()

        return {
            "total_windows": int(total),
            "HIGH_WRITE_RATE": int(w_rate),
            "MASS_FILE_MODIFICATION": int(mass_mod),
            "HIGH_ENTROPY": int(h_ent),
            "ENTROPY_INCREASE": int(ent_inc),
            "EXTENSION_CHANGES": int(ext_chg),
            "HIGH_RENAME_ACTIVITY": int(high_ren),
        }

    return {
        "normal": rule_counts(normal_df),
        "benign": rule_counts(benign_df),
        "attack_positive": rule_counts(attack_pos_df),
    }


def calibrate_rules():
    train_df = pd.read_csv(TRAIN_CSV)
    val_df = pd.read_csv(VAL_CSV)

    candidate_cfg = {
        "writes_per_sec_thresh": 20.0,
        "files_modified_thresh": 30,
        "mean_entropy_thresh": 7.0,
        "entropy_change_thresh": 1.5,
        "ext_change_count_thresh": 3,
        "rename_ratio_thresh": 0.50,
        "min_rename_count": 5,
    }

    train_eval = evaluate_rules_on_df(train_df, candidate_cfg)
    val_eval = evaluate_rules_on_df(val_df, candidate_cfg)

    report = {
        "rule_config": candidate_cfg,
        "train_triggers": train_eval,
        "validation_triggers": val_eval,
        "calibration_summary": (
            "Rule set calibrated on TRAIN & VALIDATION. "
            "HIGH_RENAME_ACTIVITY requires both rename_ratio >= 0.50 and files_renamed >= 5. "
            "HIGH_ENTROPY remains calibrated at 7.0 bits/byte Shannon scale."
        ),
    }

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[SUCCESS] Saved rule calibration to: {OUTPUT_JSON}")

    print("\n--- VALIDATION RULE TRIGGERS ---")
    print(json.dumps(val_eval, indent=2))

    return candidate_cfg


if __name__ == "__main__":
    calibrate_rules()
