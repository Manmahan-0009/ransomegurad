"""
RansomGuard - Grouped Dataset Splitter (training/split_by_run.py)

Splits dataset_v1.csv into train.csv, validation.csv, and test.csv by run_id.

CRITICAL PREVENTATIVE RULE:
Never randomly split individual rows/windows. All rows belonging to a single run_id
must remain strictly in ONE split to prevent data leakage across window overlaps.

Target Split Ratio: ~60% Train / ~20% Validation / ~20% Test (grouped by run_id).
For 3 runs per class (pilot dataset):
- Train      : 1 normal, 1 benign, 1 attack
- Validation : 1 normal, 1 benign, 1 attack
- Test       : 1 normal, 1 benign, 1 attack
"""

import csv
import json
import random
import argparse
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from training.run_recorder import get_datasets_dir, get_splits_dir
from training.generate_dataset import CSV_FIELDNAMES


def split_dataset_by_run_id(
    dataset_csv: Optional[Path] = None,
    seed: int = 42,
    train_ratio: float = 0.60,
    val_ratio: float = 0.20,
    test_ratio: float = 0.20,
) -> Dict[str, Any]:
    """
    Performs grouped, stratified train/validation/test split on dataset_v1.csv.
    Ensures zero run_id leakage across splits and class representation per split.
    """
    if dataset_csv is None:
        dataset_csv = get_datasets_dir() / "dataset_v1.csv"

    if not dataset_csv.exists() or dataset_csv.stat().st_size == 0:
        raise FileNotFoundError(f"Dataset CSV not found or empty: {dataset_csv}")

    rows_by_run: Dict[str, List[Dict[str, Any]]] = {}
    class_by_run: Dict[str, str] = {}

    with open(dataset_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row["run_id"]
            rcls = row["class"]
            if rid not in rows_by_run:
                rows_by_run[rid] = []
                class_by_run[rid] = rcls
            rows_by_run[rid].append(row)

    unique_runs = list(rows_by_run.keys())

    # Group run_ids by class to preserve stratification
    runs_by_class: Dict[str, List[str]] = {}
    for rid, rcls in class_by_run.items():
        runs_by_class.setdefault(rcls, []).append(rid)

    rng = random.Random(seed)

    train_runs: List[str] = []
    val_runs: List[str] = []
    test_runs: List[str] = []

    # Assign runs per class to splits
    for rcls in sorted(runs_by_class.keys()):
        rids = sorted(runs_by_class[rcls])
        rng.shuffle(rids)
        n = len(rids)

        if n == 1:
            train_runs.extend(rids)
        elif n == 2:
            train_runs.append(rids[0])
            test_runs.append(rids[1])
        elif n == 3:
            # Pilot 3 runs/class -> 1 train, 1 val, 1 test
            train_runs.append(rids[0])
            val_runs.append(rids[1])
            test_runs.append(rids[2])
        else:
            n_train = max(1, int(round(n * train_ratio)))
            n_val = max(1, int(round(n * val_ratio)))
            n_test = n - n_train - n_val
            if n_test < 1 and n >= 3:
                n_test = 1
                n_train = max(1, n_train - 1)

            train_runs.extend(rids[:n_train])
            val_runs.extend(rids[n_train:n_train + n_val])
            test_runs.extend(rids[n_train + n_val:])

    # Verify no run_id appears in multiple splits
    train_set = set(train_runs)
    val_set = set(val_runs)
    test_set = set(test_runs)

    assert not (train_set & val_set), "Data leakage: train and val share run_ids"
    assert not (train_set & test_set), "Data leakage: train and test share run_ids"
    assert not (val_set & test_set), "Data leakage: val and test share run_ids"

    splits_dir = get_splits_dir()

    manifest = {
        "dataset_source": str(dataset_csv),
        "seed": seed,
        "total_runs": len(unique_runs),
        "splits": {
            "train": {"run_count": len(train_runs), "run_ids": train_runs},
            "validation": {"run_count": len(val_runs), "run_ids": val_runs},
            "test": {"run_count": len(test_runs), "run_ids": test_runs},
        },
    }

    def write_split_csv(filename: str, rids: List[str]) -> Path:
        out_path = splits_dir / filename
        split_rows = []
        for rid in rids:
            split_rows.extend(rows_by_run[rid])

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(split_rows)
        return out_path

    write_split_csv("train.csv", train_runs)
    write_split_csv("validation.csv", val_runs)
    write_split_csv("test.csv", test_runs)

    manifest_path = splits_dir / "split_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    # Calculate class counts per split for summary output
    def count_classes(rids: List[str]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for rid in rids:
            cls = class_by_run[rid]
            counts[cls] = counts.get(cls, 0) + 1
        return counts

    train_cls_counts = count_classes(train_runs)
    val_cls_counts = count_classes(val_runs)
    test_cls_counts = count_classes(test_runs)

    print("\n==================================================")
    print("      DATASET RUN-BASED SPLITTING COMPLETED       ")
    print("==================================================")
    print("TRAIN")
    for cls_k in ["normal", "benign", "attack"]:
        print(f"  {cls_k:<8}: {train_cls_counts.get(cls_k, 0)}")
    print("\nVALIDATION")
    for cls_k in ["normal", "benign", "attack"]:
        print(f"  {cls_k:<8}: {val_cls_counts.get(cls_k, 0)}")
    print("\nTEST")
    for cls_k in ["normal", "benign", "attack"]:
        print(f"  {cls_k:<8}: {test_cls_counts.get(cls_k, 0)}")
    print("")
    print(f"Total Runs       : {len(unique_runs)}")
    print(f"Split Manifest   : {manifest_path}")
    print("==================================================")

    return manifest


def main():
    parser = argparse.ArgumentParser(description="RansomGuard Dataset Grouped Splitter")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for split reproducibility (default: 42)")
    args = parser.parse_args()

    split_dataset_by_run_id(seed=args.seed)


if __name__ == "__main__":
    main()
