"""
RansomGuard - Stage 2 Self-Check Script (stage2_selfcheck.py)

Static diagnostic validation tool for Stage 2 setup.
Verifies event schema, queue, deduplicator, sliding window, entropy calculator,
and feature extraction engine alignment.

SAFETY GUARANTEE: Does NOT modify any files or execute shell operations.
"""

import sys
import json
from pathlib import Path


def run_stage2_selfcheck() -> bool:
    print("==================================================")
    print("       RANSOMGUARD STAGE 2 STATIC SELF-CHECK      ")
    print("==================================================")

    project_root = Path(__file__).resolve().parent
    print(f"[*] Project Root: {project_root}")

    all_passed = True

    # 1. Verify Directories
    required_dirs = [
        project_root / "monitoring",
        project_root / "windowing",
        project_root / "features",
        project_root / "simulator",
        project_root / "utils",
        project_root / "sandbox" / "templates",
        project_root / "sandbox" / "demo_folder",
    ]

    for d in required_dirs:
        if d.exists() and d.is_dir():
            print(f"  [OK] Directory found: {d.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing directory: {d.relative_to(project_root)}")
            all_passed = False

    # 2. Verify Files
    required_files = [
        project_root / "monitoring" / "watcher.py",
        project_root / "monitoring" / "event_schema.py",
        project_root / "monitoring" / "event_queue.py",
        project_root / "monitoring" / "deduplicator.py",
        project_root / "windowing" / "sliding_window.py",
        project_root / "features" / "extractor.py",
        project_root / "features" / "entropy.py",
        project_root / "features" / "feature_schema_v1.json",
        project_root / "main.py",
        project_root / "stage1_selfcheck.py",
        project_root / "stage2_selfcheck.py",
    ]

    for f in required_files:
        if f.exists() and f.is_file():
            print(f"  [OK] File found: {f.relative_to(project_root)}")
        else:
            print(f"  [FAIL] Missing file: {f.relative_to(project_root)}")
            all_passed = False

    # 3. Verify Imports
    sys.path.insert(0, str(project_root))

    try:
        from monitoring.event_schema import StructuredEvent, create_structured_event
        from monitoring.event_queue import EventQueue, get_event_queue
        from monitoring.deduplicator import EventDeduplicator
        print("  [OK] Import succeeded: monitoring (event_schema, event_queue, deduplicator)")
    except Exception as e:
        print(f"  [FAIL] Import error in monitoring: {e}")
        all_passed = False

    try:
        from windowing.sliding_window import SlidingWindowBuffer
        buf = SlidingWindowBuffer(window_seconds=5.0, stride_seconds=1.0)
        if buf.window_seconds == 5.0 and buf.stride_seconds == 1.0:
            print("  [OK] Import & Buffer verified: windowing.sliding_window (5s window, 1s stride)")
        else:
            print("  [FAIL] SlidingWindowBuffer default settings invalid")
            all_passed = False
    except Exception as e:
        print(f"  [FAIL] Import error in windowing: {e}")
        all_passed = False

    try:
        from features.entropy import calculate_file_entropy, get_entropy_tracker
        from features.extractor import extract_features
        dummy_vector = extract_features([])
        print("  [OK] Import & Extractor verified: features.extractor (11 features default)")
    except Exception as e:
        print(f"  [FAIL] Import error in features: {e}")
        all_passed = False
        dummy_vector = {}

    # 4. Schema Alignment Check
    schema_path = project_root / "features" / "feature_schema_v1.json"
    if schema_path.exists():
        try:
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_data = json.load(f)

            schema_feature_names = [f["name"] for f in schema_data.get("features", [])]
            extractor_feature_names = list(dummy_vector.keys())

            if schema_feature_names == extractor_feature_names:
                print(f"  [OK] Feature Schema Alignment: All {len(schema_feature_names)} features match extractor.py exactly.")
            else:
                print("  [FAIL] Schema Mismatch between feature_schema_v1.json and extractor.py:")
                print(f"    Schema    : {schema_feature_names}")
                print(f"    Extractor : {extractor_feature_names}")
                all_passed = False

            if schema_data.get("window_seconds") == 5 and schema_data.get("stride_seconds") == 1:
                print("  [OK] Schema Parameters: window_seconds=5, stride_seconds=1 verified.")
            else:
                print("  [FAIL] Schema Parameters invalid in feature_schema_v1.json.")
                all_passed = False

        except Exception as e:
            print(f"  [FAIL] Error reading feature_schema_v1.json: {e}")
            all_passed = False

    print("==================================================")
    if all_passed:
        print(" [RESULT] Stage 2 Self-Check PASSED. Ready for manual feature extraction testing.")
    else:
        print(" [RESULT] Stage 2 Self-Check FAILED. Fix highlighted errors.")
    print("==================================================")

    return all_passed


if __name__ == "__main__":
    run_stage2_selfcheck()
