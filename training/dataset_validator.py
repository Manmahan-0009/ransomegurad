"""
RansomGuard - Dataset Validator Module (training/dataset_validator.py)

Comprehensive dataset sanity validator. Enforces strict correctness:
- Feature schema column consistency with feature_schema_v1.json
- Zero data leakage across train/validation/test run_id splits
- Binary labels (strictly 0 or 1)
- Correct label assignment (normal/benign = 0, attack = 1 only if attack op inside window)
- Non-zero attack window rows and positive labels
- Class presence across dataset and splits
- Numeric sanity (no NaN / Inf values)
"""

import csv
import json
import math
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

from training.run_recorder import (
    get_datasets_dir,
    get_splits_dir,
    get_run_metadata_dir,
    load_run_metadata,
    load_ground_truth_ops,
)


def validate_dataset_and_splits() -> bool:
    """
    Validates dataset_v1.csv, split_manifest.json, and train/validation/test split files.
    Returns True if ALL sanity checks pass, else False.
    """
    print("==================================================")
    print("       RANSOMGUARD DATASET SANITY VALIDATOR       ")
    print("==================================================")

    project_root = Path(__file__).resolve().parent.parent
    schema_path = project_root / "features" / "feature_schema_v1.json"
    dataset_csv = get_datasets_dir() / "dataset_v1.csv"
    splits_dir = get_splits_dir()

    all_passed = True

    # 1. Feature schema check
    if not schema_path.exists():
        print(f"  [FAIL] Missing schema file: {schema_path}")
        return False

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_data = json.load(f)
    schema_feature_names = [feat["name"] for feat in schema_data.get("features", [])]
    expected_header = ["run_id", "class", "window_start", "window_end", "label"] + schema_feature_names

    if not dataset_csv.exists() or dataset_csv.stat().st_size == 0:
        print(f"  [FAIL] dataset_v1.csv does not exist or is empty.")
        return False

    rows: List[Dict[str, Any]] = []
    with open(dataset_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        if header != expected_header:
            print("  [FAIL] CSV Header mismatch with feature_schema_v1.json")
            print(f"    Expected: {expected_header}")
            print(f"    Actual  : {header}")
            all_passed = False
        else:
            print("  [OK] Feature schema matches")

        for r in reader:
            rows.append(r)

    if not rows:
        print("  [FAIL] dataset_v1.csv contains 0 feature rows.")
        return False

    # 2. Aggregations & class counts
    runs_by_class: Dict[str, Set[str]] = {"normal": set(), "benign": set(), "attack": set()}
    rows_by_class: Dict[str, int] = {"normal": 0, "benign": 0, "attack": 0}
    rows_per_run: Dict[str, int] = {}
    label_counts = {0: 0, 1: 0}

    normal_benign_violations = 0
    attack_label_violations = 0
    attack_underlabel_violations = 0
    nan_inf_violations = 0
    invalid_label_violations = 0

    for idx, row in enumerate(rows):
        rid = row["run_id"]
        rcls = row["class"].lower()
        lbl_str = row["label"]

        if rcls in runs_by_class:
            runs_by_class[rcls].add(rid)
            rows_by_class[rcls] += 1

        rows_per_run[rid] = rows_per_run.get(rid, 0) + 1

        if lbl_str not in ["0", "1"]:
            invalid_label_violations += 1
            lbl = -1
        else:
            lbl = int(lbl_str)
            label_counts[lbl] += 1

        # Normal and Benign rows MUST be 0
        if rcls in ["normal", "benign"] and lbl != 0:
            normal_benign_violations += 1

        w_start = float(row["window_start"])
        w_end = float(row["window_end"])
        if w_start > w_end:
            print(f"  [FAIL] Invalid window timestamps at row {idx}: start={w_start} > end={w_end}")
            all_passed = False

        # Attack timing ground-truth verification
        if rcls == "attack":
            ops = load_ground_truth_ops(rid)
            has_op_in_window = any(w_start <= op.get("operation_time", 0.0) < w_end for op in ops)

            if lbl == 1 and not has_op_in_window:
                attack_label_violations += 1
            elif lbl == 0 and has_op_in_window:
                attack_underlabel_violations += 1

        # Numeric sanity check
        for feat in schema_feature_names:
            val_str = row.get(feat, "0")
            try:
                val = float(val_str)
                if math.isnan(val) or math.isinf(val):
                    nan_inf_violations += 1
            except ValueError:
                nan_inf_violations += 1

    # Print detailed counts
    normal_run_cnt = len(runs_by_class["normal"])
    benign_run_cnt = len(runs_by_class["benign"])
    attack_run_cnt = len(runs_by_class["attack"])
    total_runs_cnt = len(rows_per_run)

    print("\n--- DATASET SUMMARY COUNTS ---")
    print(f"Normal runs      : {normal_run_cnt}")
    print(f"Benign runs      : {benign_run_cnt}")
    print(f"Attack runs      : {attack_run_cnt}")
    print(f"Total runs       : {total_runs_cnt}")
    print("")
    print(f"Normal rows      : {rows_by_class['normal']}")
    print(f"Benign rows      : {rows_by_class['benign']}")
    print(f"Attack rows      : {rows_by_class['attack']}")
    print(f"Total rows       : {len(rows)}")
    print("")
    print(f"Positive labels  : {label_counts[1]}")
    print(f"Negative labels  : {label_counts[0]}")
    print("------------------------------\n")

    # Check required classes presence
    if normal_run_cnt > 0 and benign_run_cnt > 0 and attack_run_cnt > 0:
        print("  [OK] Dataset contains all required classes")
    else:
        print(f"  [FAIL] Dataset missing required classes! normal={normal_run_cnt}, benign={benign_run_cnt}, attack={attack_run_cnt}")
        all_passed = False

    if normal_run_cnt > 0:
        print("  [OK] Normal runs present")
    else:
        print("  [FAIL] Normal runs missing")
        all_passed = False

    if benign_run_cnt > 0:
        print("  [OK] Benign runs present")
    else:
        print("  [FAIL] Benign runs missing")
        all_passed = False

    if attack_run_cnt > 0 and rows_by_class["attack"] > 0:
        print("  [OK] Attack runs present")
    else:
        print("  [FAIL] Attack runs missing or produce 0 feature rows")
        all_passed = False

    if label_counts[1] > 0:
        print("  [OK] Positive attack labels present")
    else:
        print("  [FAIL] Zero positive attack labels in dataset")
        all_passed = False

    # Check zero-row runs against run_metadata JSONs
    meta_dir = get_run_metadata_dir()
    meta_runs = [f.stem for f in meta_dir.glob("*.json") if not f.name.endswith("_attack_ops.json")]
    zero_row_runs = [rid for rid in meta_runs if rid not in rows_per_run or rows_per_run[rid] == 0]

    if not zero_row_runs:
        print("  [OK] No run generated zero feature windows")
    else:
        print(f"  [FAIL] Runs with zero feature windows detected: {zero_row_runs}")
        all_passed = False

    if normal_benign_violations == 0 and invalid_label_violations == 0:
        print("  [OK] Normal/benign labels all 0")
    else:
        print(f"  [FAIL] Label violations found in normal/benign runs: {normal_benign_violations}")
        all_passed = False

    if attack_label_violations == 0 and attack_underlabel_violations == 0:
        print("  [OK] Attack label timing verified")
    else:
        print(f"  [FAIL] Attack label timing violations: false_positive={attack_label_violations}, false_negative={attack_underlabel_violations}")
        all_passed = False

    if nan_inf_violations == 0:
        print("  [OK] Numeric sanity passed")
    else:
        print(f"  [FAIL] Numeric sanity failed ({nan_inf_violations} NaN/Inf values)")
        all_passed = False

    # 3. Split Manifest & Data Leakage Checks
    manifest_path = splits_dir / "split_manifest.json"
    if manifest_path.exists():
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        train_runs = set(manifest["splits"]["train"]["run_ids"])
        val_runs = set(manifest["splits"]["validation"]["run_ids"])
        test_runs = set(manifest["splits"]["test"]["run_ids"])

        train_val_overlap = train_runs.intersection(val_runs)
        train_test_overlap = train_runs.intersection(test_runs)
        val_test_overlap = val_runs.intersection(test_runs)

        if not train_val_overlap and not train_test_overlap and not val_test_overlap:
            print("  [OK] Run IDs disjoint across splits")
        else:
            print(f"  [FAIL] Data leakage detected across splits! Overlaps: {train_val_overlap | train_test_overlap | val_test_overlap}")
            all_passed = False

        # Class representation per split check
        def get_split_classes(rids: Set[str]) -> Set[str]:
            res = set()
            for r in rids:
                for rcls, rset in runs_by_class.items():
                    if r in rset:
                        res.add(rcls)
            return res

        train_classes = get_split_classes(train_runs)
        val_classes = get_split_classes(val_runs)
        test_classes = get_split_classes(test_runs)

        required_classes = {"normal", "benign", "attack"}
        if train_classes == required_classes and val_classes == required_classes and test_classes == required_classes:
            print("  [OK] Required class representation exists in each split")
        else:
            print("  [FAIL] Missing required classes in splits:")
            print(f"    Train classes : {train_classes}")
            print(f"    Val classes   : {val_classes}")
            print(f"    Test classes  : {test_classes}")
            all_passed = False
    else:
        print("  [WARN] split_manifest.json does not exist yet. Run split-data first.")

    print("==================================================")
    if all_passed:
        print(" [RESULT] Stage 3 Dataset Validation PASSED")
    else:
        print(" [RESULT] Stage 3 Dataset Validation FAILED")
    print("==================================================")

    return all_passed


def main():
    passed = validate_dataset_and_splits()
    if not passed:
        exit(1)


if __name__ == "__main__":
    main()
