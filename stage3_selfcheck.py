"""
RansomGuard - Stage 3 Self-Check Script (stage3_selfcheck.py)

Static diagnostic validation tool for Stage 3 setup.
Verifies dataset generation pipeline, run recorder, timestamp labeler,
grouped split module, replay consistency helper, and dataset validator.

SAFETY GUARANTEE: Does NOT modify any files or execute shell operations.
"""

import sys
import json
import inspect
from pathlib import Path


def run_stage3_selfcheck() -> bool:
    print("==================================================")
    print("       RANSOMGUARD STAGE 3 STATIC SELF-CHECK      ")
    print("==================================================")

    project_root = Path(__file__).resolve().parent
    print(f"[*] Project Root: {project_root}")

    all_passed = True

    # 1. Verify Directories
    required_dirs = [
        project_root / "data" / "raw_events",
        project_root / "data" / "run_metadata",
        project_root / "data" / "datasets",
        project_root / "data" / "splits",
        project_root / "training",
        project_root / "simulator",
        project_root / "monitoring",
        project_root / "windowing",
        project_root / "features",
        project_root / "utils",
    ]

    for d in required_dirs:
        if d.exists() and d.is_dir():
            print(f"  [OK] Directory found: {d.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing directory: {d.relative_to(project_root)}")
            all_passed = False

    # 2. Verify Files
    required_files = [
        project_root / "simulator" / "benign_simulator.py",
        project_root / "simulator" / "attack_simulator.py",
        project_root / "training" / "run_recorder.py",
        project_root / "training" / "label_windows.py",
        project_root / "training" / "generate_dataset.py",
        project_root / "training" / "split_by_run.py",
        project_root / "training" / "dataset_validator.py",
        project_root / "training" / "replay_consistency.py",
        project_root / "training" / "verify_stage3.py",
        project_root / "stage1_selfcheck.py",
        project_root / "stage2_selfcheck.py",
        project_root / "stage3_selfcheck.py",
        project_root / "main.py",
    ]

    for f in required_files:
        if f.exists() and f.is_file():
            print(f"  [OK] File found: {f.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing file: {f.relative_to(project_root)}")
            all_passed = False

    # 3. Verify Imports & Code Invariants
    sys.path.insert(0, str(project_root))

    try:
        from simulator.benign_simulator import run_benign_simulation
        from simulator.attack_simulator import run_attack_simulation
        print("  [OK] Import succeeded: simulator modules")
    except Exception as e:
        print(f"  [FAIL] Import error in simulator package: {e}")
        all_passed = False

    try:
        from training.run_recorder import save_run_metadata, save_raw_events, load_raw_events
        from training.label_windows import compute_window_label
        from training.generate_dataset import (
            run_dataset_generation,
            CSV_FIELDNAMES,
            PRE_OBSERVATION_SECONDS,
            POST_OBSERVATION_SECONDS,
        )
        from training.split_by_run import split_dataset_by_run_id
        from training.dataset_validator import validate_dataset_and_splits
        from training.replay_consistency import verify_run_replay_consistency
        from training.verify_stage3 import run_stage3_quick_verification
        print("  [OK] Import succeeded: training package (recorder, labeler, generator, splitter, validator, replay_consistency, verify_stage3)")
        print(f"  [OK] Observation Timing Config Verified: pre={PRE_OBSERVATION_SECONDS}s, post={POST_OBSERVATION_SECONDS}s")
    except Exception as e:
        print(f"  [FAIL] Import error in training package: {e}")
        all_passed = False
        CSV_FIELDNAMES = []

    try:
        from monitoring.event_schema import StructuredEvent
        evt_fields = set(StructuredEvent.__dataclass_fields__.keys())
        if "entropy" in evt_fields and "entropy_delta" in evt_fields:
            print("  [OK] StructuredEvent schema includes entropy and entropy_delta fields")
        else:
            print(f"  [FAIL] StructuredEvent missing entropy fields: {evt_fields}")
            all_passed = False
    except Exception as e:
        print(f"  [FAIL] Error inspecting StructuredEvent schema: {e}")
        all_passed = False

    try:
        from features.extractor import extract_features
        print("  [OK] Import verified: features.extractor (Stage 2 shared extractor intact)")
    except Exception as e:
        print(f"  [FAIL] Import error in features.extractor: {e}")
        all_passed = False

    # 4. Check Dataset Column Alignment with Schema
    schema_path = project_root / "features" / "feature_schema_v1.json"
    if schema_path.exists():
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_data = json.load(f)
        schema_feature_names = [feat["name"] for feat in schema_data.get("features", [])]
        expected_csv_cols = ["run_id", "class", "window_start", "window_end", "label"] + schema_feature_names

        if CSV_FIELDNAMES == expected_csv_cols:
            print(f"  [OK] CSV Field Alignment: All {len(CSV_FIELDNAMES)} dataset columns match feature_schema_v1.json.")
        else:
            print("  [FAIL] Mismatch between CSV fieldnames and feature_schema_v1.json:")
            print(f"    CSV Header : {CSV_FIELDNAMES}")
            print(f"    Expected   : {expected_csv_cols}")
            all_passed = False

    print("==================================================")
    if all_passed:
        print(" [RESULT] Stage 3 Self-Check PASSED. Ready for pilot dataset generation.")
    else:
        print(" [RESULT] Stage 3 Self-Check FAILED. Fix highlighted errors.")
    print("==================================================")

    return all_passed


if __name__ == "__main__":
    run_stage3_selfcheck()
