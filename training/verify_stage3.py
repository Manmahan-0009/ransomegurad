"""
RansomGuard - Stage 3 Quick Verification Module (training/verify_stage3.py)

Fast, non-destructive diagnostic command for re-verifying existing Stage 3 dataset artifacts:
- Dataset & manifest SHA-256 fingerprints
- Artifact completeness (raw events, metadata, ground-truth attack ops)
- Timestamp ordering and validity
- Run coverage and class distribution
- Label correctness & timestamp alignment
- Grouped split zero data leakage & class presence
- Entropy ranges per class (mean_entropy & entropy_change)
- Replay consistency check for 1 normal, 1 benign, 1 attack run
"""

import csv
import json
import math
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional

from training.run_recorder import (
    get_datasets_dir,
    get_splits_dir,
    get_raw_events_dir,
    get_run_metadata_dir,
    load_run_metadata,
    load_ground_truth_ops,
    load_raw_events,
)
from training.replay_consistency import verify_run_replay_consistency
from training.dataset_validator import validate_dataset_and_splits


def calculate_file_sha256(filepath: Path) -> str:
    """Calculates SHA-256 hex digest of a file if it exists."""
    if not filepath.exists() or not filepath.is_file():
        return "FILE_NOT_FOUND"
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def run_stage3_quick_verification() -> bool:
    """
    Executes fast, non-destructive verification of existing Stage 3 artifacts.
    Returns True if ALL checks pass, else False.
    """
    print("==================================================")
    print("      RANSOMGUARD STAGE 3 QUICK VERIFICATION      ")
    print("==================================================")

    project_root = Path(__file__).resolve().parent.parent
    schema_path = project_root / "features" / "feature_schema_v1.json"
    dataset_csv = get_datasets_dir() / "dataset_v1.csv"
    splits_dir = get_splits_dir()
    manifest_path = splits_dir / "split_manifest.json"

    all_passed = True

    # 1. Dataset Fingerprints (SHA-256)
    print("\nDataset Fingerprints (SHA-256)")
    print("------------------------------")
    ds_hash = calculate_file_sha256(dataset_csv)
    manifest_hash = calculate_file_sha256(manifest_path)
    schema_hash = calculate_file_sha256(schema_path)

    print(f"dataset_v1.csv        : {ds_hash}")
    print(f"split_manifest.json   : {manifest_hash}")
    print(f"feature_schema_v1.json: {schema_hash}")

    if ds_hash == "FILE_NOT_FOUND" or manifest_hash == "FILE_NOT_FOUND":
        print("\n  [FAIL] Core Stage 3 dataset or manifest files missing.")
        print("  Please generate dataset and perform split first by running:\n")
        print("    python main.py generate-data --all --runs-per-class 3 --seed 42 --fresh")
        print("    python main.py split-data --seed 42\n")
        return False

    # 2. Artifact Completeness Check
    print("\nArtifact Completeness")
    print("---------------------")

    missing_artifacts: List[str] = []
    rows: List[Dict[str, Any]] = []

    with open(dataset_csv, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    if not rows:
        print("  [FAIL] dataset_v1.csv is empty.")
        return False

    runs_by_class: Dict[str, Set[str]] = {"normal": set(), "benign": set(), "attack": set()}
    rows_by_class: Dict[str, int] = {"normal": 0, "benign": 0, "attack": 0}
    rows_per_run: Dict[str, List[Dict[str, Any]]] = {}

    for r in rows:
        rid = r["run_id"]
        rcls = r["class"].lower()
        if rcls in runs_by_class:
            runs_by_class[rcls].add(rid)
            rows_by_class[rcls] += 1
        rows_per_run.setdefault(rid, []).append(r)

    raw_dir = get_raw_events_dir()
    meta_dir = get_run_metadata_dir()

    all_run_ids = set(rows_per_run.keys())

    for rid in all_run_ids:
        raw_f = raw_dir / f"{rid}.jsonl"
        meta_f = meta_dir / f"{rid}.json"

        if not raw_f.exists():
            missing_artifacts.append(f"raw_events/{rid}.jsonl")
        if not meta_f.exists():
            missing_artifacts.append(f"run_metadata/{rid}.json")

        if rid.startswith("attack_"):
            ops_f = meta_dir / f"{rid}_attack_ops.jsonl"
            if not ops_f.exists():
                missing_artifacts.append(f"run_metadata/{rid}_attack_ops.jsonl")

    if not missing_artifacts:
        print("  [OK] All raw event JSONL files exist")
        print("  [OK] All run metadata JSON files exist")
        print("  [OK] All ground-truth attack operation files exist")
    else:
        print(f"  [FAIL] Missing artifacts detected ({len(missing_artifacts)} files):")
        for m in missing_artifacts[:5]:
            print(f"    - {m}")
        all_passed = False

    # 3. Timestamp & Window Ordering Sanity Check
    print("\nTimestamp & Window Sanity")
    print("-------------------------")

    timestamp_violations = 0
    ordering_violations = 0
    metadata_timestamp_violations = 0

    for rid, run_rows in rows_per_run.items():
        prev_w_start = -1.0
        for row in run_rows:
            w_start = float(row["window_start"])
            w_end = float(row["window_end"])

            if w_start >= w_end:
                timestamp_violations += 1

            if w_start < prev_w_start:
                ordering_violations += 1
            prev_w_start = w_start

        # Check metadata timestamp bounds
        try:
            meta = load_run_metadata(rid)
            start_t = meta.get("start_time", 0.0)
            end_t = meta.get("end_time", 0.0)
            if start_t > end_t:
                metadata_timestamp_violations += 1

            if rid.startswith("attack_"):
                ops = load_ground_truth_ops(rid)
                for op in ops:
                    op_t = op.get("operation_time", 0.0)
                    if op_t < start_t or op_t > end_t + 5.0:
                        metadata_timestamp_violations += 1
        except Exception:
            metadata_timestamp_violations += 1

    if timestamp_violations == 0 and ordering_violations == 0 and metadata_timestamp_violations == 0:
        print("  [OK] Window intervals valid (window_start < window_end)")
        print("  [OK] Chronological window ordering verified per run")
        print("  [OK] Metadata start/end timestamps valid")
    else:
        print(f"  [FAIL] Timestamp violations found: interval={timestamp_violations}, order={ordering_violations}, meta={metadata_timestamp_violations}")
        all_passed = False

    # 4. Entropy Distribution Summary per Class
    print("\nEntropy Distribution Summary")
    print("----------------------------")

    entropy_stats: Dict[str, Dict[str, List[float]]] = {
        "normal": {"mean_entropy": [], "entropy_change": []},
        "benign": {"mean_entropy": [], "entropy_change": []},
        "attack": {"mean_entropy": [], "entropy_change": []},
    }

    all_mean_entropies: List[float] = []
    all_entropy_changes: List[float] = []

    for row in rows:
        rcls = row["class"].lower()
        if rcls in entropy_stats:
            m_ent = float(row.get("mean_entropy", 0.0))
            e_chg = float(row.get("entropy_change", 0.0))
            entropy_stats[rcls]["mean_entropy"].append(m_ent)
            entropy_stats[rcls]["entropy_change"].append(e_chg)
            all_mean_entropies.append(m_ent)
            all_entropy_changes.append(e_chg)

    for cname in ["normal", "benign", "attack"]:
        m_list = entropy_stats[cname]["mean_entropy"]
        e_list = entropy_stats[cname]["entropy_change"]

        m_min, m_max = (min(m_list), max(m_list)) if m_list else (0.0, 0.0)
        e_min, e_max = (min(e_list), max(e_list)) if e_list else (0.0, 0.0)

        print(f"{cname}:")
        print(f"  mean_entropy min/max   : {m_min:.4f} / {m_max:.4f}")
        print(f"  entropy_change min/max : {e_min:.4f} / {e_max:.4f}")

    all_zero_entropy = (
        all(m == 0.0 for m in all_mean_entropies) and all(e == 0.0 for e in all_entropy_changes)
    )

    if all_zero_entropy:
        print("\n  [FAIL] All entropy values across the entire dataset are 0.0!")
        all_passed = False
    else:
        print("\n  [OK] Entropy measurements present (non-zero dataset)")

    # 5. Offline Replay Consistency (1 run per class)
    print("\nReplay Consistency (1 Run Per Class)")
    print("------------------------------------")

    replay_passed = True
    for cname in ["normal", "benign", "attack"]:
        c_runs = sorted(list(runs_by_class[cname]))
        if not c_runs:
            print(f"  [FAIL] No {cname} runs available to test replay consistency.")
            replay_passed = False
            all_passed = False
            continue

        test_rid = c_runs[0]
        saved_run_rows = rows_per_run[test_rid]

        ok, msg = verify_run_replay_consistency(run_id=test_rid, live_windows=saved_run_rows, tolerance=1e-4)
        if ok:
            print(f"  [OK] Replay consistency: {cname} ({test_rid})")
        else:
            print(f"  [FAIL] Replay consistency: {cname} ({test_rid}) - {msg}")
            replay_passed = False
            all_passed = False

    # 6. Run Coverage & Core Dataset Validator Check
    print("\nDataset Integrity & Split Validation")
    print("-------------------------------------")
    validator_ok = validate_dataset_and_splits()
    if not validator_ok:
        all_passed = False

    print("==================================================")
    if all_passed:
        print(" [RESULT] Stage 3 Quick Verification PASSED")
    else:
        print(" [RESULT] Stage 3 Quick Verification FAILED")
    print("==================================================")

    return all_passed


def main():
    passed = run_stage3_quick_verification()
    if not passed:
        exit(1)


if __name__ == "__main__":
    main()
